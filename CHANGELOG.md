## 2.4

* Added `BKA` order type.
* Optimized upload transaction.
* Fix decryption for data.
* Optimized memory usage.

## 2.3

* Support specify custom keyring details for Electronic Signature.
* Support switching A005/A006
* Change signature for KeyringManagerInterface. Attributes `USER.A.Version` moved from Bank to Keyring.
* Add `withES` param for downloading order types. Default `withES=false`.
* Extended OrderData handler.
* Add CountryCode for FUL.
* Add Parameters for FDL.
* Add ParserFormat for BTD.
* Client methods signatures refactoring.

## 2.2

* Change signature for KeyringManagerInterface. Attributes `IsCertified`, `Version` moved from Bank to Keyring.
* Change signature for EbicsInterface. Attributes `X509Generator`, moved from EbicsClient to Keyring `certificateGenerator`.
* Remove UTF-8 encoding for content.
* Support EBICS TS mode.
* Add 'xml_files' parser for order data.
* Updated BTD method signature.
* Added support for EBICS version 2.4.
* Added option to specify custom PDF Factory.
* Changed pdf generator to FPDF.
* Add methods `XEK` order type for EBICS 3.0
* Add method to check keyring.
* Add method to change keyring password.
* Changed logic for certificate storing into keyring.

## 2.1

* Up supported PHP version to >= 7.4
* Add `FUL`, `H3K` order type for EBICS 2.5
* Add methods `YCT`, `ZSR`, `Z54` order type for EBICS 3.0
* Major update for keyring manager. Added Array & File keyring managers instead of keyring.
* Add responseHandler into ClientInterface
* Add $storageCallback for download methods that handle acknowledge.
* Fix UTF-8 encoding.
* Added CurlHttpClient and PsrHttpClient to use standard client.
* Updated AbstractX509Generator to handle custom options.
* Improved Bank-letter
* Fixed padding for encoding that caused problems for upload methods.
* Added XE3
* Fixed CCT, CDD builder.
