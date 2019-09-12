<?php

namespace AndrewSvirin\tests\Unit;

use AndrewSvirin\Ebics\handlers\AuthSignatureHandler;
use AndrewSvirin\Ebics\handlers\traits\XPathTrait;
use AndrewSvirin\Ebics\models\Bank;
use AndrewSvirin\Ebics\EbicsClient;
use AndrewSvirin\Ebics\exceptions\EbicsException;
use AndrewSvirin\Ebics\models\Certificate;
use AndrewSvirin\Ebics\models\KeyRing;
use AndrewSvirin\Ebics\models\Request;
use AndrewSvirin\Ebics\services\CryptService;
use AndrewSvirin\Ebics\services\KeyRingManager;
use AndrewSvirin\Ebics\models\User;
use PHPUnit\Framework\TestCase;

/**
 * Class EbicsTest.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
final class AuthSignatureHandlerTest extends TestCase
{

   use XPathTrait;

   var $data = __DIR__ . '/../_data';
   var $fixtures = __DIR__ . '/../_fixtures';

   /**
    * @var EbicsClient
    */
   private $client;

   /**
    * @var KeyRingManager
    */
   private $keyRingManager;

   /**
    * @var KeyRing
    */
   private $keyRing;

   /**
    * @throws EbicsException
    */
   public function setUp()
   {
      parent::setUp();
      $credentials = json_decode(file_get_contents($this->data . '/credentials_2.json'));
      $keyRingRealPath = $this->data . '/workspace/keyring_2.json';
      $this->keyRingManager = new KeyRingManager($keyRingRealPath, 'test123');
      $this->keyRing = $this->keyRingManager->loadKeyRing();
      $bank = new Bank($credentials->hostId, $credentials->hostURL, $credentials->hostIsCertified);
      $user = new User($credentials->partnerId, $credentials->userId);
      $this->client = new EbicsClient($bank, $user, $this->keyRing);
   }

   /**
    * Generate auth signature for working example.
    * @group DigestValue
    * @throws EbicsException
    */
   public function testDigestValue()
   {
      $authSignatureHandler = new AuthSignatureHandler(new CryptService($this->keyRing));

      $hpb = file_get_contents($this->fixtures . '/hpb.xml');
      $hpbXML = new Request();
      $hpbXML->loadXML($hpb);
      $hpbXPath = $this->prepareH004XPath($hpbXML);

      $hpb2XML = clone $hpbXML;
      $hpb2XPath = $this->prepareH004XPath($hpb2XML);
      $hpb2Request = $hpb2XPath->query('/H004:ebicsNoPubKeyDigestsRequest')->item(0);
      $authSignature2 = $hpb2XPath->query('//H004:AuthSignature')->item(0);
      $authSignature2->parentNode->removeChild($authSignature2);

      $authSignatureHandler->handle($hpb2XML, $hpb2Request);

      // Rewind. Because after remove and insert XML tree do not work correctly.
      $hpb2XML->loadXML($hpb2XML->saveXML());
      $hpb2XPath = $this->prepareH004XPath($hpb2XML);

      $digestValue = $hpbXPath->query('//H004:AuthSignature/ds:SignedInfo/ds:Reference/ds:DigestValue')->item(0)->nodeValue;
      $digestValue2 = $hpb2XPath->query('//H004:AuthSignature/ds:SignedInfo/ds:Reference/ds:DigestValue')->item(0)->nodeValue;
      $this->assertEquals($digestValue, $digestValue2);
   }

   /**
    * Generate auth signature for working example.
    * @group SignatureValue
    * @throws EbicsException
    */
   public function testSignatureValue()
   {
      $keys = json_decode(file_get_contents($this->fixtures . '/keys.json'));
      $this->keyRing->setPassword('mysecret');
      $this->keyRing->setUserCertificateX(new Certificate(
         $this->keyRing->getUserCertificateX()->getContent(),
         $this->keyRing->getUserCertificateX()->getType(),
         $this->keyRing->getUserCertificateX()->getPublicKey(),
         $keys->X002
      ));

      $authSignatureHandler = new AuthSignatureHandler(new CryptService($this->keyRing));

      $hpb = file_get_contents($this->fixtures . '/hpb.xml');
      $request = new Request();
      $request->loadXML($hpb);
      $requestXpath = $this->prepareH004XPath($request);
      $digestValue = $requestXpath->query('//H004:AuthSignature/ds:SignatureValue')->item(0)->nodeValue;

      $request2 = clone $request;
      $request2XPath = $this->prepareH004XPath($request2);

      $authSignature2 = $request2XPath->query('//H004:AuthSignature')->item(0);
      $authSignature2->parentNode->removeChild($authSignature2);

      $request2Request = $request2XPath->query('/H004:ebicsNoPubKeyDigestsRequest')->item(0);
      $authSignatureHandler->handle($request2, $request2Request);

      // Rewind. Because after remove and insert XML tree do not work correctly.
      $request2->loadXML($request2->saveXML());
      $request2XPath = $this->prepareH004XPath($request2);

      $digestValue2 = $request2XPath->query('//H004:AuthSignature/ds:SignatureValue')->item(0)->nodeValue;

      $c = $request2->getContent();

      $this->assertEquals($digestValue, $digestValue2);
      // TODO: Fails.
   }
}