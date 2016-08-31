import 'dart:typed_data';
import 'dart:io';
import 'dart:math';
import 'package:otp/otp.dart';
import 'package:cipher/cipher.dart';
import 'package:cipher/impl/server.dart';
import 'package:cipher/params/key_parameter.dart';
import 'package:cipher/params/key_derivators/scrypt_parameters.dart';

main(List<String> args){
  stdin.echoMode = false;

  initCipher();

  if (args.isEmpty){
    displayPins();
    exit(0);
  }
  if (args[0] == "-h" || args[0] == "--help" || args[0] == "help"){
    displayHelp();
    exit(0);
  }
  if (args[0] == "addKey") {
    if (args.length < 3) {
      print("forgot either key or label of key");
      print("dart main.dart addKey szsdfo5157zefd1f5sd4857fgsdf84s4 google");
      exit(0);
    }
    addKey(args);
    exit(0);
  }
}

void displayHelp(){
  print("normal use :");
  print("dart main.dart");
  print("it will display each generated pin with its label and the name of file storing your key");
  print("example : 666666 google 15431.key");
  print("");
  print("adding a key");
  print("dart main.dart addKey szsdfo5157zefd1f5sd4857fgsdf84s4 google");
  print("it will create a key file with the encrypted label as name and with the encrypter key in it.");
  print("Each encrypted with the password you will enter");
}

void addKey(List<String> args){
  String generatingKey = args[1];
  String label         = args[2];

  stdout.write("Password :");
  String password = stdin.readLineSync();
  stdout.writeln("");

  String salt = "geras48t";
  var scryptParams = new ScryptParameters(pow(2,16), 8, 1, 32, new Uint8List.fromList(salt.codeUnits));
  var keyDerivator = new KeyDerivator("scrypt")..init(scryptParams);

  var key = keyDerivator.process(new Uint8List.fromList(password.codeUnits));

  var params = new KeyParameter(key);
  var ivparams = new ParametersWithIV(params, new Uint8List(16));
  var cipher = new BlockCipher("AES/CTR")..init(true, ivparams);

  label = label.replaceAll("-", "~");

  List<String> toEncrypt = new List();
  String temp = label + "";
  while(temp.length > 0){
    if (temp.length < 16) for (int i = temp.length; i < 16; i++) temp += "-";
    toEncrypt.add(temp.substring(0, 16));
    if (temp.length != 0) temp = temp.substring(16, temp.length);
  }

  List<String> toWrite = new List();
  for (int i = 0; i < toEncrypt.length; i++) {
    Uint8List clearBits = new Uint8List.fromList(toEncrypt[i].codeUnits);
    toWrite.add(new String.fromCharCodes(cipher.process(clearBits)));
    params = new KeyParameter(clearBits);
    ivparams = new ParametersWithIV(params, new Uint8List(16));
    cipher.reset();
    cipher.init(true, ivparams);
  }

  label = toWrite.join(" ");

  cipher.reset();
  cipher.init(true, ivparams);

  toEncrypt = new List();
  temp = generatingKey + "";
  while(temp.length > 0){
    if (temp.length < 16) for (int i = temp.length; i < 16; i++) temp += "-";
    toEncrypt.add(temp.substring(0, 16));
    if (temp.length != 0) temp = temp.substring(16, temp.length);
  }

  toWrite = new List();
  for (int i = 0; i < toEncrypt.length; i++){
    Uint8List clearBits = new Uint8List.fromList(toEncrypt[i].codeUnits);
    toWrite.add(new String.fromCharCodes(cipher.process(clearBits)));
    params = new KeyParameter(clearBits);
    ivparams = new ParametersWithIV(params, new Uint8List(16));
    cipher.reset();
    cipher.init(true, ivparams);
  }

  File f;
  int rand;
  do {
    rand = new Random().nextInt(200000);
  } while (new File("keys/$rand.key").existsSync());
  f = new File("keys/$rand.key");
  f.createSync(recursive: true);
  f.writeAsStringSync(toWrite.join(" ") + "  " + label);
}

void displayPins(){
  stdout.write("Password :");
  String password = stdin.readLineSync();
  stdout.writeln("");

  List<String> generatingKeys = new List();
  List<String> labels = new List();
  List<String> filenames = new List();

  String salt = "geras48t";
  var scryptParams = new ScryptParameters(pow(2,16), 8, 1, 32, new Uint8List.fromList(salt.codeUnits));
  var keyDerivator = new KeyDerivator("scrypt")..init(scryptParams);

  var key = keyDerivator.process(new Uint8List.fromList(password.codeUnits));

  var params = new KeyParameter(key);
  var ivparams = new ParametersWithIV(params, new Uint8List(16));
  var cipher = new BlockCipher("AES/CTR")..init(false, ivparams);

  Directory d = new Directory("keys");
  if (!d.existsSync()){
    print("no keys, use addKey as first argument to add ones");
    exit(0);
  }
  d.listSync(recursive: false, followLinks: false).forEach((FileSystemEntity f){
    if (f.path.endsWith(".key")){
      filenames.add(f.uri.pathSegments.last);
      File trueF = f;
      String fileContent = trueF.readAsStringSync();

      String enc_key = fileContent.split("  ")[0];
      String enc_label = fileContent.split("  ")[1];

      List<Uint8List> toDecrypt = new List();
      enc_label.split(" ").forEach((String s){ toDecrypt.add(new Uint8List.fromList(s.codeUnits)); });

      var params = new KeyParameter(key);
      var ivparams = new ParametersWithIV(params, new Uint8List(16));

      cipher.reset();
      cipher.init(false, ivparams);

      List<String> decrypted = new List();
      for (int i = 0; i < toDecrypt.length; i++){
        Uint8List decryptedBits = cipher.process(toDecrypt[i]);
        decrypted.add(new String.fromCharCodes(decryptedBits));
        params = new KeyParameter(decryptedBits);
        ivparams = new ParametersWithIV(params, new Uint8List(16));
        cipher.reset();
        cipher.init(false, ivparams);
      }

      labels.add(decrypted.join().replaceAll("-", "").replaceAll("~", "-"));

      toDecrypt = new List();
      enc_key.split(" ").forEach((String s){ toDecrypt.add(new Uint8List.fromList(s.codeUnits)); });

      cipher.reset();
      cipher.init(false, ivparams);

      decrypted = new List();
      for (int i = 0; i < toDecrypt.length; i++){
        Uint8List decryptedBits = cipher.process(toDecrypt[i]);
        decrypted.add(new String.fromCharCodes(decryptedBits));
        params = new KeyParameter(decryptedBits);
        ivparams = new ParametersWithIV(params, new Uint8List(16));
        cipher.reset();
        cipher.init(false, ivparams);
      }

      generatingKeys.add(decrypted.join().replaceAll("-", ""));
    }
  });

  int now = new DateTime.now().millisecondsSinceEpoch;

  for (int i = 0; i < generatingKeys.length; i++){
    String pin = OTP.generateTOTPCode(generatingKeys[i], now).toString();
    String label = labels[i];
    String filename = filenames[i];
    print("$pin $label from $filename");
  }
}