import 'dart:typed_data';

class DataBufferReader {
  DataBufferReader(
    this.byteData, {
    this.offsetInBytes = 0,
    this.endian = Endian.little,
  });

  final ByteData byteData;
  final Endian endian;
  int offsetInBytes;

  int get lengthInBytes => byteData.lengthInBytes;

  int get remainingBytes => lengthInBytes - offsetInBytes;

  /// [length] is the count of Uint8's
  Uint8List readUint8List(int length) {
    final value = byteData.buffer.asUint8List(byteData.offsetInBytes + offsetInBytes, length);
    offsetInBytes += length;
    return value;
  }

  /// [length] is the count of Uint16's
  Uint16List readUint16List(int length) {
    final value = byteData.buffer.asUint16List(byteData.offsetInBytes + offsetInBytes, length);
    offsetInBytes += length * 2;
    return value;
  }

  int readUint8() {
    final value = byteData.getUint8(offsetInBytes);
    offsetInBytes += Uint8List.bytesPerElement;
    return value;
  }

  int readUint16() {
    final value = byteData.getUint16(offsetInBytes, endian);
    offsetInBytes += Uint16List.bytesPerElement;
    return value;
  }

  int readUint32() {
    final value = byteData.getUint32(offsetInBytes, endian);
    offsetInBytes += Uint32List.bytesPerElement;
    return value;
  }

  int readIUint64() {
    final value = byteData.getUint64(offsetInBytes, endian);
    offsetInBytes += Uint64List.bytesPerElement;
    return value;
  }

  int readInt8() {
    final value = byteData.getInt8(offsetInBytes);
    offsetInBytes += Int8List.bytesPerElement;
    return value;
  }

  int readInt16() {
    final value = byteData.getInt16(offsetInBytes, endian);
    offsetInBytes += Int16List.bytesPerElement;
    return value;
  }

  int readInt32() {
    final value = byteData.getInt32(offsetInBytes, endian);
    offsetInBytes += Int32List.bytesPerElement;
    return value;
  }

  int readInt64() {
    final value = byteData.getInt64(offsetInBytes, endian);
    offsetInBytes += Int64List.bytesPerElement;
    return value;
  }

  double readFloat32() {
    final value = byteData.getFloat32(offsetInBytes, endian);
    offsetInBytes += Float32List.bytesPerElement;
    return value;
  }

  double readFloat64() {
    final value = byteData.getFloat64(offsetInBytes, endian);
    offsetInBytes += Float64List.bytesPerElement;
    return value;
  }
}
