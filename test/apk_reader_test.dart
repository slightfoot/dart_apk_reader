import 'dart:io';

import 'package:apk_reader/apk_reader.dart';
import 'package:test/test.dart';

void main() {
  test('test apk-reader', () {
    final apkReader = ApkReader.open(File('test.apk').readAsBytesSync());
    print('cert sha1: ${apkReader.sha1Fingerprint}');
    print('cert sha256: ${apkReader.sha256Fingerprint}');
    print('debuggable: ${apkReader.debuggable}');
    print('appName: ${apkReader.appName}');
    print('versionName: ${apkReader.versionName}');
    print('versionCode: ${apkReader.versionCode}');
    print('packageName: ${apkReader.packageName}');
    print('minSdkVersion: ${apkReader.minSdkVersion}');
    print('targetSdkVersion: ${apkReader.targetSdkVersion}');
    print('icon: ${apkReader.appIcon.length}');
    print('permissions: ${apkReader.permissions}');
    print('\n');
  });
}
