import 'dart:convert' show utf8;
import 'dart:typed_data';

import 'package:archive/archive_io.dart';
import 'package:pkcs7/pkcs7.dart';

import 'buffer.dart';
import 'res_attrs.dart';
import 'res_types.dart';

class ApkReader {
  ApkReader(this.archive, this.manifest, this.resources, this.cert);

  static ApkReader open(Uint8List buffer) {
    final archive = ZipDecoder().decodeBuffer(InputStream(buffer));

    Uint8List? getFileBytes(String filename) {
      final file = archive.findFile(filename)?..decompress();
      return file?.content as Uint8List;
    }

    final androidManifest = getFileBytes('AndroidManifest.xml');
    final resources = getFileBytes('resources.arsc');

    if (androidManifest == null || resources == null) {
      throw 'Not a valid APK file';
    }

    // If we don't have a cert we'll assume we're not signed
    final certRsa = getFileBytes('META-INF/CERT.RSA');
    final cert = certRsa != null ? Pkcs7.fromDer(certRsa) : null;

    return ApkReader(
      archive,
      androidManifest,
      resources,
      cert,
    );
  }

  final Archive archive;
  final Uint8List manifest;
  final Uint8List resources;
  final Pkcs7? cert;

  Uint8List get _der => cert!.certificates.first.der;

  String? get sha1Fingerprint =>
      cert != null ? cert!.toHex(cert!.getDigest(HashAlgorithm.sha1).process(_der)) : null;

  String? get sha256Fingerprint =>
      cert != null ? cert!.toHex(cert!.getDigest(HashAlgorithm.sha256).process(_der)) : null;

  bool get debuggable => (getAttribute('manifest/application', 'debuggable') ?? 'false') == 'true';

  String get appName => getAttribute('manifest/application', 'label')!;

  Uint8List get appIcon => getImage('manifest/application', 'icon');

  String get versionName => getAttribute('manifest', 'versionName')!;

  int get versionCode => int.parse(getAttribute('manifest', 'versionCode')!);

  String get packageName => getAttribute('manifest', 'package')!;

  String get platformBuildVersionName => getAttribute('manifest', 'platformBuildVersionName')!;

  int get minSdkVersion => int.parse(getAttribute('manifest/uses-sdk', 'minSdkVersion')!);

  int get targetSdkVersion => int.parse(getAttribute('manifest/uses-sdk', 'targetSdkVersion')!);

  List<String> get permissions {
    return quickSearchManifestXml('manifest/uses-permission', 'name');
  }

  Uint8List getImage(String tag, String attr) {
    final path = quickSearchManifestXml(tag, attr);
    if (path.isEmpty) {
      throw Exception('Cannot find image for <$tag>.<$attr>');
    }
    final file = archive.findFile(path[0])!;
    file.decompress();
    return file.content as Uint8List;
  }

  String? getAttribute(String tag, String attr) {
    final result = quickSearchManifestXml(tag, attr);
    if (result.isEmpty) {
      return null;
    }
    return result[0];
  }

  List<String> quickSearchManifestXml(String tag, String attribute) {
    return quickSearchCompressedXml(manifest, tag, attribute);
  }

  List<String> quickSearchCompressedXml(Uint8List xml, String xpath, String attribute) {
    final results = <String>[];
    final path = xpath.split('/')..removeWhere((el) => el.isEmpty);
    final br = DataBufferReader(ByteData.sublistView(xml));
    br.offsetInBytes = 8; // skip first 8 bytes
    int tagDepth = 0;
    int matchDepth = 0;
    while (br.remainingBytes > 0) {
      final chunkPos = br.offsetInBytes;
      final chunkType = ResType.forInt(br.readInt16());
      final headerSize = br.readInt16();
      final chunkSize = br.readInt32();
      if (chunkType == ResType.xmlStartElementType) {
        tagDepth++;
        br.offsetInBytes += 8 + 4; // skip line number & comment / namespace
        final tagString = quickSearchCompressedXmlStringPoolAndResMap(xml, br.readUint32());
        if (tagDepth <= path.length &&
            tagString.toUpperCase() == path[tagDepth - 1].toUpperCase()) {
          matchDepth++;
          if (matchDepth == path.length) {
            // match, read attributes
            int attributeStart = br.readInt16();
            int attributeSize = br.readInt16();
            int attributeCount = br.readInt16();
            for (int i = 0; i < attributeCount; i++) {
              int offset = headerSize + attributeStart + attributeSize * i + 4;
              if (offset >= chunkSize) {
                // Error: comes to out of chunk
                throw Exception('Out of Chunk when processing tag $tagString');
              }
              br.offsetInBytes = chunkPos + offset; // ignore the ns
              int ind = br.readUint32();
              final name = quickSearchCompressedXmlStringPoolAndResMap(xml, ind);
              if (name.toUpperCase() == attribute.toUpperCase()) {
                br.offsetInBytes += 4 + 2 + 1; // skip rawValue/size/0/
                final dataType = ResDataType.forInt(br.readUint8())!;
                int data = br.readUint32();
                results.add(convertData(xml, dataType, data));
              }
            }
          }
        }
      } else if (chunkType == ResType.xmlEndElementType) {
        if (matchDepth == tagDepth) {
          matchDepth--;
        }
        tagDepth--;
      }
      br.offsetInBytes = chunkPos + chunkSize;
    }
    return results;
  }

  String convertData(Uint8List bytes, ResDataType type, int data) {
    switch (type) {
      case ResDataType.typeString:
        return quickSearchStringPool(bytes, data);
      case ResDataType.typeReference:
        try {
          final r = quickSearchResource(data);
          // for (int i = 0; i < r.length; i++) {
          //   print('$i: ${r.configs[i]} : ${r.values[i]}');
          // }
          return r.values[0].toString();
        } catch (error, stackTrace) {
          print('$error\n$stackTrace');
          return '(0x${data.toRadixString(16).padLeft(8, '0')})';
        }
      case ResDataType.typeIntBool:
        return (data == 0) ? 'true' : 'false';
      case ResDataType.typeDimension:
        final type = ResComplexUnitType.forInt(data & 0xff)!;
        return (data >> 8).toString() + type.suffix;
      case ResDataType.typeFloat:
        final buffer = ByteData(Int32List.bytesPerElement);
        buffer.setInt32(0, data);
        return buffer.getFloat32(0).toString();
      case ResDataType.typeIntColorARGB8:
      case ResDataType.typeIntColorARGB4:
      case ResDataType.typeIntColorRGB4:
      case ResDataType.typeIntColorRGB8:
        return '#${data.toRadixString(16).padLeft(8, '0')}';
      default:
        return data.toString();
    }
  }

  String quickSearchCompressedXmlStringPoolAndResMap(Uint8List xml, int id) {
    if (id == 0xffffffff) return '';
    String result = quickSearchStringPool(xml, id);
    if (result == '') {
      result = quickSearchCompressedXmlResMap(xml, id);
      if (result == '') {
        result = '(0x${id.toRadixString(16).padLeft(8, '0')})';
      }
    }
    return result;
  }

  String quickSearchStringPool(Uint8List bytes, int id) {
    if (id == 0xffffffff) return '';
    final br = DataBufferReader(ByteData.sublistView(bytes));
    var chunkType = ResType.forInt(br.readInt16());
    int headerSize = br.readInt16();
    br.offsetInBytes = headerSize;
    while (br.offsetInBytes < br.lengthInBytes) {
      int chunkPos = br.offsetInBytes;
      chunkType = ResType.forInt(br.readInt16());
      headerSize = br.readInt16();
      int chunkSize = br.readInt32();
      if (chunkType == ResType.resStringPoolType) {
        //int stringCount = br.readInt32();
        //int styleCount = br.readInt32();
        br.offsetInBytes += 8;
        int flags = br.readInt32();
        bool isUTF_8 = (flags & (1 << 8)) != 0;
        int stringStart = br.readInt32();
        br.offsetInBytes += 4 + id * 4;
        int stringPos = br.readInt32();
        br.offsetInBytes = chunkPos + stringStart + stringPos;
        if (isUTF_8) {
          br.readUint8(); // skip?
          int u8len = br.readUint8();
          if ((u8len & 0x80) != 0) {
            // larger than 128
            u8len = ((u8len & 0x7F) << 8) + br.readUint8();
          }
          final raw = br.readUint8List(u8len);
          final str = utf8.decode(raw);
          return str;
        } else {
          // UTF_16
          int u16len = br.readUint16();
          if ((u16len & 0x8000) != 0) {
            // larger than 32768
            u16len = ((u16len & 0x7FFF) << 16) + br.readUint16();
          }
          final raw = br.readUint16List(u16len);
          final str = String.fromCharCodes(raw);
          // print('string2 $id => $raw => "$str"');
          return str;
        }
      } else {
        br.offsetInBytes = chunkPos + chunkSize;
      }
    }
    return '';
  }

  String quickSearchCompressedXmlResMap(Uint8List xml, int id) {
    if (id == 0xffffffff) return '';
    final br = DataBufferReader(ByteData.sublistView(xml));
    var chunkType = ResType.forInt(br.readInt16());
    int headerSize = br.readInt16();
    br.offsetInBytes = headerSize;
    while (br.offsetInBytes < br.lengthInBytes) {
      int chunkPos = br.offsetInBytes;
      chunkType = ResType.forInt(br.readInt16());
      headerSize = br.readInt16();
      int chunkSize = br.readInt32();
      if (chunkType == ResType.xmlResourceMapType) {
        // Resource map
        br.offsetInBytes += id * 4;
        final result = ResAttribute.forInt(br.readUint32())?.name;
        if (result != null) {
          return result;
        }
        return '';
      } else {
        br.offsetInBytes = chunkPos + chunkSize;
      }
    }
    return '';
  }

  // for handling loop reference
  final _searchStack = <int>[];

  ApkResource quickSearchResource(int id) {
    _searchStack.add(id);
    final res = ApkResource(id);
    final br = DataBufferReader(ByteData.sublistView(resources));
    br.offsetInBytes = 8; // jump type/headersize/chunksize
    int packageCount = br.readInt32();
    // comes to stringpool chunk, skipit
    // int stringPoolPos = br.offsetInBytes;
    br.offsetInBytes += 4;
    int stringPoolSize = br.readInt32();
    br.offsetInBytes += stringPoolSize - 8; // jump to the end
    // Package chunk now
    for (int pack = 0; pack < packageCount; pack++) {
      int packChunkPos = br.offsetInBytes;
      // print('pack $pack of $packageCount @ ${packChunkPos.toRadixString(16)}');
      br.offsetInBytes += 2; // jump type/headersize
      int headerSize = br.readInt16();
      int packChunkSize = br.readInt32();
      int packId = br.readInt32();
      // print('pack $packId : $headerSize $packChunkSize');
      if (packId != res.packageId) {
        // check if the resource is in this pack goto next chunk
        br.offsetInBytes = packChunkPos + packChunkSize;
        continue;
      } else {
        br.offsetInBytes = packChunkPos + headerSize;
        br.offsetInBytes += 4; // skip type-string chunk
        final stringChunkSize = br.readInt32();
        br.offsetInBytes += stringChunkSize - 8; // jump to the end
        br.offsetInBytes += 4; // skip key-string chunk
        final keyChunkSize = br.readInt32();
        br.offsetInBytes += keyChunkSize - 8; // jump to the end

        // print('stringChunkSize=$stringChunkSize, keyChunkSize=$keyChunkSize');

        // come to typespec chunks and type chunks
        // typespec and type chunks may happen in a row.
        // print('chunkOffset=${br.offsetInBytes}');
        do {
          final chunkPos = br.offsetInBytes;
          final chunkType = ResType.forInt(br.readInt16());
          headerSize = br.readInt16();
          int chunkSize = br.readInt32();
          int typeId;

          // print('chunkType=${chunkType?.value.toRadixString(16)}, chunkSize=$chunkSize, chunkOffset=${br.offsetInBytes}');

          if (chunkType == ResType.tableTypeType) {
            typeId = br.readUint8();
            if (typeId == res.typeId) {
              br.offsetInBytes += 3; // skip 0
              //int entryCount = br.readInt32();
              br.offsetInBytes += 4;
              int entryStart = br.readInt32();
              // read the config section
              int configSize = br.readInt32();
              final conf = br.readUint8List(configSize - 4);
              br.offsetInBytes = chunkPos + headerSize + res.entryId * 4;
              int entryIndic = br.readUint32();
              if (entryIndic == 0xffffffff) {
                // no entry here, go to next chunk
                br.offsetInBytes = chunkPos + chunkSize;
                continue;
              }
              br.offsetInBytes = chunkPos + entryStart + entryIndic; // get to the entry
              br.offsetInBytes += 11; // skip entry size, flags, key, size, 0
              final dataType = ResDataType.forInt(br.readUint8());
              int data = br.readUint32();
              if (dataType == ResDataType.typeString) {
                final string = quickSearchStringPool(resources, data);
                res.addConfig(conf, string);
              } else if (dataType == ResDataType.typeReference) {
                // the entry is null, or it's referencing in loop, go to next chunk
                if (data == 0x00000000 || _searchStack.contains(data)) {
                  br.offsetInBytes = chunkPos + chunkSize;
                  continue;
                }
                res.add(quickSearchResource(data));
              } else {
                // I would like to expect we only will recieve
                // TYPE_STRING/TYPE_REFERENCE/any integer type,
                // complex is not considering here, yet
                res.addConfig(conf, data.toString());
              }
            }
          }
          br.offsetInBytes = chunkPos + chunkSize; // skip this chunk
        } while (br.offsetInBytes < packChunkPos + packChunkSize);
      }
    }
    _searchStack.removeLast();
    return res;
  }
}

class ApkResource {
  ApkResource(this.id);

  final int id;
  final configs = <Uint8List>[];
  final values = <dynamic>[];

  int get packageId => (id & 0xff000000) >> 24;

  int get typeId => (id & 0x00ff0000) >> 16;

  int get entryId => (id & 0x0000ffff);

  set defaultValue(dynamic value) {
    if (configs.isEmpty) {
      configs.add(Uint8List(0));
    } else {
      configs[0] = Uint8List(0);
    }
    if (values.isEmpty) {
      values.add(value);
    } else {
      values[0] = value;
    }
  }

  dynamic get defaultValue {
    if (length >= 1) {
      return values[0];
    } else {
      return null;
    }
  }

  int get length {
    return configs.length;
  }

  void addConfig(Uint8List config, Object value) {
    configs.add(config);
    values.add(value);
  }

  void add(dynamic value) {
    if (value is Uint8List) {
    } else if (value is ApkResource) {
      for (int i = 0; i < value.length; i++) {
        addConfig(value.configs[i], value.values[i]);
      }
    } else {
      configs.add(Uint8List(0));
      values.add(value);
    }
  }
}
