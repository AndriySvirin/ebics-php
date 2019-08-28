<?php

namespace AndrewSvirin\Ebics;

use AndrewSvirin\Ebics\factories\CertificateFactory;
use AndrewSvirin\Ebics\handlers\BodyHandler;
use AndrewSvirin\Ebics\handlers\HeaderHandler;
use AndrewSvirin\Ebics\handlers\OrderDataHandler;
use AndrewSvirin\Ebics\handlers\RequestHandler;
use AndrewSvirin\Ebics\models\OrderData;
use AndrewSvirin\Ebics\models\Request;
use AndrewSvirin\Ebics\models\Response;
use DOMDocument;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\Exception\ClientExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\RedirectionExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\ServerExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;

/**
 * EBICS client representation.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
class Client
{

   /**
    * An EbicsBank instance.
    * @var Bank
    */
   private $bank;

   /**
    * An EbicsUser instance.
    * @var User
    */
   private $user;

   /**
    * @var RequestHandler
    */
   private $requestHandler;

   /**
    * @var HeaderHandler
    */
   private $headerHandler;

   /**
    * @var BodyHandler
    */
   private $bodyHandler;

   /**
    * @var KeyRing
    */
   private $keyRing;

   /**
    * @var OrderDataHandler
    */
   private $orderDataHandler;

   /**
    * Constructor.
    * @param Bank $bank
    * @param User $user
    * @param KeyRing $keyRing
    */
   public function __construct(Bank $bank, User $user, KeyRing $keyRing)
   {
      $this->bank = $bank;
      $this->user = $user;
      $this->keyRing = $keyRing;
      $this->requestHandler = new RequestHandler();
      $this->headerHandler = new HeaderHandler($bank, $user);
      $this->bodyHandler = new BodyHandler();
      $this->orderDataHandler = new OrderDataHandler($user, $keyRing);
   }

   /**
    * Getter for bank.
    * @return Bank
    */
   public function getBank()
   {
      return $this->bank;
   }

   /**
    * Getter for user.
    * @return User
    */
   public function getUser()
   {
      return $this->user;
   }

   /**
    * @param string $body
    * @return ResponseInterface
    * @throws TransportExceptionInterface
    */
   private function post($body): ResponseInterface
   {
      $httpClient = HttpClient::create();
      $response = $httpClient->request('POST', $this->bank->getUrl(), [
         'headers' => [
            'Content-Type' => 'text/xml; charset=ISO-8859-1',
         ],
         'body' => $body,
         'verify_peer' => false,
         'verify_host' => false,
      ]);
      return $response;
   }

   /**
    * Make INI request.
    * @return Response
    * @throws ClientExceptionInterface
    * @throws RedirectionExceptionInterface
    * @throws ServerExceptionInterface
    * @throws TransportExceptionInterface
    */
   public function INI(): Response
   {
      $certificateA = CertificateFactory::buildCertificateA();
      // Order data.
      $orderData = new OrderData();
      $this->orderDataHandler->handle($orderData, $certificateA);
      $orderDataContent = $orderData->getContent();
      // Wrapper for request Order data.
      $request = new Request();
      $xmlRequest = $this->requestHandler->handleUnsecured($request);
      $this->headerHandler->handleINI($request, $xmlRequest);
      $this->bodyHandler->handle($request, $xmlRequest, $orderDataContent);
      $requestContent = $request->getContent();
      $hostResponse = $this->post($requestContent);
      $hostResponseContent = $hostResponse->getContent();
      $response = new Response();
      $response->loadXML($hostResponseContent);
      return $response;
   }

   /**
    * Make HIA request.
    * @param $data
    * @return string
    * @throws ClientExceptionInterface
    * @throws RedirectionExceptionInterface
    * @throws ServerExceptionInterface
    * @throws TransportExceptionInterface
    */
   public function HIA($data)
   {
      $certificateE = CertificateFactory::buildCertificateE();
      $certificateEX509 = $certificateE->toX509();
      $certificateX = CertificateFactory::buildCertificateX();
      $certificateXX509 = $certificateX->toX509();
      $exponent1 = $certificateEX509->getPublicKey()->exponent->toHex();
      $modulus1 = $certificateEX509->getPublicKey()->modulus->toHex();
      $exponent2 = $certificateXX509->getPublicKey()->exponent->toHex();
      $modulus2 = $certificateXX509->getPublicKey()->modulus->toHex();
      $data = str_replace([
         '{X002_Modulus}',
         '{X002_Exponent}',
         '{E002_Modulus}',
         '{E002_Exponent}',
         '{XX509IssuerName}',
         '{XX509SerialNumber}',
         '{XX509Certificate}',
         '{EX509IssuerName}',
         '{EX509SerialNumber}',
         '{EX509Certificate}',
         '{PartnerID}',
         '{UserID}',
      ], [
         base64_encode($modulus1),
         base64_encode($exponent1),
         base64_encode($modulus2),
         base64_encode($exponent2),
         $certificateEX509->getInsurerName(),
         $certificateEX509->getSerialNumber(),
         base64_encode($certificateE->getContent()),
         $certificateXX509->getInsurerName(),
         $certificateXX509->getSerialNumber(),
         base64_encode($certificateX->getContent()),
         $this->user->getPartnerId(),
         $this->user->getUserId(),

      ], $data);
      $xml = '<?xml version="1.0"?>
        <ebicsUnsecuredRequest xmlns="urn:org:ebics:H004" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Revision="1" Version="H004">
          <header authenticate="true">
            <static>
              <HostID>' . $this->bank->getHostId() . '</HostID>
              <PartnerID>' . $this->user->getPartnerId() . '</PartnerID>
              <UserID>' . $this->user->getUserId() . '</UserID>
              <OrderDetails>
                <OrderType>HIA</OrderType>
                <OrderAttribute>DZNNN</OrderAttribute>
              </OrderDetails>
              <SecurityMedium>0000</SecurityMedium>
            </static>
            <mutable/>
          </header>
          <body>
            <DataTransfer>
              <OrderData>' . base64_encode(gzcompress($data)) . '</OrderData>
            </DataTransfer>
          </body>
        </ebicsUnsecuredRequest>';
      $hostResponse = $this->post($xml);
      $hostResponseContent = $hostResponse->getContent();
      $response = new Response();
      $response->loadXML($hostResponseContent);
      return $response;
   }

   public function SPR()
   {

   }

   /**
    * Downloads the bank account statement in SWIFT format (MT940).
    * @param int $start The start date of requested transactions.
    * @param int $end The end date of requested transactions.
    * @param boolean $parsed Flag whether the received MT940 message should be
    * parsed and returned as a dictionary or not.
    * @return
    */
   public function STA($start = NULL, $end = NULL, $parsed = FALSE)
   {
      return '';
   }

   /**
    * Downloads the interim transaction report in SWIFT format (MT942).
    * @param int $start The start date of requested transactions.
    * @param int $end The end date of requested transactions.
    * @param boolean $parsed Flag whether the received MT940 message should be
    * parsed and returned as a dictionary or not.
    * @return Response
    * @throws \Comodojo\Exception\HttpException
    * @throws exceptions\EbicsException
    * @throws \Exception
    */
   public function VMK($start = NULL, $end = NULL, $parsed = FALSE)
   {
      $domTree = new DOMDocument();

      // Add OrderDetails.
      $xmlOrderDetails = $domTree->createElement('OrderDetails');
      $domTree->appendChild($xmlOrderDetails);

      // Add OrderType.
      $xmlOrderType = $domTree->createElement('OrderType');
      $xmlOrderType->nodeValue = 'VMK';
      $xmlOrderDetails->appendChild($xmlOrderType);

      // Add OrderAttribute.
      $xmlOrderAttribute = $domTree->createElement('OrderAttribute');
      $xmlOrderAttribute->nodeValue = 'DZHNN';
      $xmlOrderDetails->appendChild($xmlOrderAttribute);

      // Add StandardOrderParams.
      $xmlStandardOrderParams = $domTree->createElement('StandardOrderParams');
      $xmlOrderDetails->appendChild($xmlStandardOrderParams);

      if ($start != NULL && $end != NULL)
      {
         // Add DateRange.
         $xmlDateRange = $domTree->createElement('DateRange');
         $xmlStandardOrderParams->appendChild($xmlDateRange);

         // Add Start.
         $xmlStart = $domTree->createElement('Start');
         $xmlStart->nodeValue = $start;
         $xmlDateRange->appendChild($xmlStart);
         // Add End.
         $xmlEnd = $domTree->createElement('End');
         $xmlEnd->nodeValue = $end;
         $xmlDateRange->appendChild($xmlEnd);
      }

      $request = new Request($this);
      $orderDetails = $domTree->getElementsByTagName('OrderDetails')->item(0);

      return $request->createRequest($orderDetails)->download();
   }

}
