<?php

namespace EbicsApi\Ebics;

use DateTimeInterface;
use EbicsApi\Ebics\Builders\Request\RequestBuilder;
use EbicsApi\Ebics\Contexts\BTDContext;
use EbicsApi\Ebics\Contexts\BTUContext;
use EbicsApi\Ebics\Contexts\FDLContext;
use EbicsApi\Ebics\Contexts\FULContext;
use EbicsApi\Ebics\Contexts\HVDContext;
use EbicsApi\Ebics\Contexts\HVEContext;
use EbicsApi\Ebics\Contexts\HVTContext;
use EbicsApi\Ebics\Contexts\RequestContext;
use EbicsApi\Ebics\Contracts\EbicsClientInterface;
use EbicsApi\Ebics\Contracts\HttpClientInterface;
use EbicsApi\Ebics\Contracts\OrderDataInterface;
use EbicsApi\Ebics\Contracts\SignatureInterface;
use EbicsApi\Ebics\Exceptions\EbicsException;
use EbicsApi\Ebics\Exceptions\EbicsResponseException;
use EbicsApi\Ebics\Exceptions\IncorrectResponseEbicsException;
use EbicsApi\Ebics\Exceptions\PasswordEbicsException;
use EbicsApi\Ebics\Factories\BufferFactory;
use EbicsApi\Ebics\Factories\CertificateX509Factory;
use EbicsApi\Ebics\Factories\Crypt\BigIntegerFactory;
use EbicsApi\Ebics\Factories\DocumentFactory;
use EbicsApi\Ebics\Factories\EbicsExceptionFactory;
use EbicsApi\Ebics\Factories\EbicsFactoryV24;
use EbicsApi\Ebics\Factories\EbicsFactoryV25;
use EbicsApi\Ebics\Factories\EbicsFactoryV30;
use EbicsApi\Ebics\Factories\OrderResultFactory;
use EbicsApi\Ebics\Factories\RequestFactory;
use EbicsApi\Ebics\Factories\SegmentFactory;
use EbicsApi\Ebics\Factories\SignatureFactory;
use EbicsApi\Ebics\Factories\TransactionFactory;
use EbicsApi\Ebics\Handlers\OrderDataHandler;
use EbicsApi\Ebics\Handlers\ResponseHandler;
use EbicsApi\Ebics\Models\Bank;
use EbicsApi\Ebics\Models\DownloadOrderResult;
use EbicsApi\Ebics\Models\DownloadSegment;
use EbicsApi\Ebics\Models\DownloadTransaction;
use EbicsApi\Ebics\Models\Http\Request;
use EbicsApi\Ebics\Models\Http\Response;
use EbicsApi\Ebics\Models\InitializationOrderResult;
use EbicsApi\Ebics\Models\InitializationSegment;
use EbicsApi\Ebics\Models\InitializationTransaction;
use EbicsApi\Ebics\Models\Keyring;
use EbicsApi\Ebics\Models\UploadOrderResult;
use EbicsApi\Ebics\Models\UploadTransaction;
use EbicsApi\Ebics\Models\User;
use EbicsApi\Ebics\Models\X509\ContentX509Generator;
use EbicsApi\Ebics\Services\CryptService;
use EbicsApi\Ebics\Services\CurlHttpClient;
use EbicsApi\Ebics\Services\XmlService;
use EbicsApi\Ebics\Services\ZipService;
use LogicException;

/**
 * EBICS client representation.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
final class EbicsClient implements EbicsClientInterface
{
    private Bank $bank;
    private User $user;
    private Keyring $keyring;
    private OrderDataHandler $orderDataHandler;
    private ResponseHandler $responseHandler;
    private RequestFactory $requestFactory;
    private CryptService $cryptService;
    private ZipService $zipService;
    private XmlService $xmlService;
    private DocumentFactory $documentFactory;
    private OrderResultFactory $orderResultFactory;
    private SignatureFactory $signatureFactory;
    private HttpClientInterface $httpClient;
    private TransactionFactory $transactionFactory;
    private SegmentFactory $segmentFactory;
    private BufferFactory $bufferFactory;

    /**
     * Constructor.
     *
     * @param Bank $bank
     * @param User $user
     * @param Keyring $keyring
     * @param array $options
     */
    public function __construct(Bank $bank, User $user, Keyring $keyring, array $options = [])
    {
        $this->bank = $bank;
        $this->user = $user;
        $this->keyring = $keyring;

        if (Keyring::VERSION_24 === $keyring->getVersion()) {
            $ebicsFactory = new EbicsFactoryV24();
        } elseif (Keyring::VERSION_25 === $keyring->getVersion()) {
            $ebicsFactory = new EbicsFactoryV25();
        } elseif (Keyring::VERSION_30 === $keyring->getVersion()) {
            $ebicsFactory = new EbicsFactoryV30();
        } else {
            throw new LogicException(sprintf('Version "%s" is not implemented', $keyring->getVersion()));
        }

        $this->segmentFactory = new SegmentFactory();
        $this->cryptService = new CryptService();
        $this->zipService = new ZipService();
        $this->signatureFactory = new SignatureFactory();
        $this->bufferFactory = new BufferFactory($options['buffer_filename'] ?? 'php://memory');

        $this->orderDataHandler = $ebicsFactory->createOrderDataHandler(
            $user,
            $keyring,
            $this->cryptService,
            $this->signatureFactory,
            new CertificateX509Factory(),
            new BigIntegerFactory()
        );

        $this->requestFactory = $ebicsFactory->createRequestFactory(
            $bank,
            $user,
            $keyring,
            $ebicsFactory->createAuthSignatureHandler($keyring, $this->cryptService),
            $ebicsFactory->createUserSignatureHandler($user, $keyring, $this->cryptService),
            $this->orderDataHandler,
            $ebicsFactory->createDigestResolver($this->cryptService),
            new RequestBuilder(),
            $this->cryptService,
            $this->zipService
        );

        $this->responseHandler = $ebicsFactory->createResponseHandler(
            $this->segmentFactory,
            $this->cryptService,
            $this->zipService,
            $this->bufferFactory
        );

        $this->xmlService = new XmlService();
        $this->documentFactory = new DocumentFactory();
        $this->orderResultFactory = new OrderResultFactory();
        $this->transactionFactory = new TransactionFactory();
        $this->httpClient = $options['http_client'] ?? new CurlHttpClient();
    }

    /**
     * @inheritDoc
     * @throws EbicsException
     */
    public function createUserSignatures(array $options = null): void
    {
        $signatureA = $this->createUserSignature(SignatureInterface::TYPE_A, $options['a_details'] ?? null);
        $this->keyring->setUserSignatureAVersion($options['a_version'] ?? SignatureInterface::A_VERSION6);
        $this->keyring->setUserSignatureA($signatureA);

        $signatureE = $this->createUserSignature(SignatureInterface::TYPE_E, $options['e_details'] ?? null);
        $this->keyring->setUserSignatureE($signatureE);

        $signatureX = $this->createUserSignature(SignatureInterface::TYPE_X, $options['x_details'] ?? null);
        $this->keyring->setUserSignatureX($signatureX);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\IncorrectResponseEbicsException
     */
    public function HEV(): Response
    {
        $context = $this->requestFactory->prepareStandardContext();
        $request = $this->requestFactory->createHEV($context);
        $response = $this->httpClient->post($this->bank->getUrl(), $request);

        $this->checkH000ReturnCode($request, $response);

        return $response;
    }

    /**
     * @inheritDoc
     * @throws EbicsException
     */
    public function INI(RequestContext $context = null): Response
    {
        $context = $this->requestFactory->prepareStandardContext($context);
        $signatureA = $this->getUserSignature(SignatureInterface::TYPE_A);

        $request = $this->requestFactory->createINI($signatureA, $context);
        $response = $this->httpClient->post($this->bank->getUrl(), $request);

        $this->checkH00XReturnCode($request, $response);
        $this->keyring->setUserSignatureA($signatureA);

        return $response;
    }

    /**
     * @inheritDoc
     * @throws EbicsException
     */
    public function HIA(RequestContext $context = null): Response
    {
        $context = $this->requestFactory->prepareStandardContext($context);
        $signatureE = $this->getUserSignature(SignatureInterface::TYPE_E);
        $signatureX = $this->getUserSignature(SignatureInterface::TYPE_X);

        $request = $this->requestFactory->createHIA($signatureE, $signatureX, $context);
        $response = $this->httpClient->post($this->bank->getUrl(), $request);

        $this->checkH00XReturnCode($request, $response);
        $this->keyring->setUserSignatureE($signatureE);
        $this->keyring->setUserSignatureX($signatureX);

        return $response;
    }

    /**
     * @inheritDoc
     * @throws EbicsException
     */
    public function H3K(RequestContext $context = null): Response
    {
        $context = $this->requestFactory->prepareStandardContext($context);
        $signatureA = $this->getUserSignature(SignatureInterface::TYPE_A);
        $signatureE = $this->getUserSignature(SignatureInterface::TYPE_E);
        $signatureX = $this->getUserSignature(SignatureInterface::TYPE_X);

        $request = $this->requestFactory->createH3K($signatureA, $signatureE, $signatureX, $context);
        $response = $this->httpClient->post($this->bank->getUrl(), $request);

        $this->checkH00XReturnCode($request, $response);
        $this->keyring->setUserSignatureA($signatureA);
        $this->keyring->setUserSignatureE($signatureE);
        $this->keyring->setUserSignatureX($signatureX);

        return $response;
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsException
     */
    public function HPB(RequestContext $context = null): InitializationOrderResult
    {
        $context = $this->requestFactory->prepareStandardContext($context);
        $transaction = $this->initializeTransaction(
            function () use ($context) {
                return $this->requestFactory->createHPB($context);
            }
        );

        $orderResult = $this->createInitializationOrderResult($transaction);

        $signatureX = $this->orderDataHandler->retrieveAuthenticationSignature($orderResult->getDocument());
        $signatureE = $this->orderDataHandler->retrieveEncryptionSignature($orderResult->getDocument());
        $this->keyring->setBankSignatureX($signatureX);
        $this->keyring->setBankSignatureE($signatureE);

        return $orderResult;
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsException
     */
    public function SPR(RequestContext $context = null): UploadOrderResult
    {
        $context = $this->requestFactory->prepareStandardContext($context);
        $context->setOnlyES(true);

        $transaction = $this->uploadTransaction(
            function (UploadTransaction $transaction) use ($context) {
                $transaction->setOrderData(' ');
                $transaction->setNumSegments(0);
                $transaction->setDigest($this->cryptService->hash($transaction->getOrderData()));

                return $this->requestFactory->createSPR($transaction, $context);
            }
        );

        return $this->createUploadESResult($transaction, $transaction->getDigest());
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsException
     */
    public function HPD(RequestContext $context = null): DownloadOrderResult
    {
        $context = $this->requestFactory->prepareStandardContext($context);
        $transaction = $this->downloadTransaction(
            function () use ($context) {
                return $this->requestFactory->createHPD($context);
            }
        );

        return $this->createDownloadOrderResult($transaction, self::FILE_PARSER_FORMAT_XML);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsException
     */
    public function HKD(RequestContext $context = null): DownloadOrderResult
    {
        $context = $this->requestFactory->prepareStandardContext($context);
        $transaction = $this->downloadTransaction(
            function () use ($context) {
                return $this->requestFactory->createHKD($context);
            }
        );

        return $this->createDownloadOrderResult($transaction, self::FILE_PARSER_FORMAT_XML);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsException
     */
    public function HTD(RequestContext $context = null): DownloadOrderResult
    {
        $context = $this->requestFactory->prepareStandardContext($context);
        $transaction = $this->downloadTransaction(
            function () use ($context) {
                return $this->requestFactory->createHTD($context);
            }
        );

        return $this->createDownloadOrderResult($transaction, self::FILE_PARSER_FORMAT_XML);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsException
     */
    public function HAA(RequestContext $context = null): DownloadOrderResult
    {
        $context = $this->requestFactory->prepareStandardContext($context);
        $transaction = $this->downloadTransaction(
            function () use ($context) {
                return $this->requestFactory->createHAA($context);
            }
        );

        return $this->createDownloadOrderResult($transaction, self::FILE_PARSER_FORMAT_XML);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsException
     */
    public function PTK(
        DateTimeInterface $startDateTime = null,
        DateTimeInterface $endDateTime = null,
        RequestContext $context = null
    ): DownloadOrderResult {
        $context = $this->requestFactory->prepareDownloadContext($context)
            ->setStartDateTime($startDateTime)
            ->setEndDateTime($endDateTime);
        $transaction = $this->downloadTransaction(
            function () use ($context) {
                return $this->requestFactory->createPTK($context);
            }
        );

        return $this->createDownloadOrderResult($transaction, self::FILE_PARSER_FORMAT_TEXT);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsException
     */
    public function VMK(
        DateTimeInterface $startDateTime = null,
        DateTimeInterface $endDateTime = null,
        RequestContext $context = null
    ): DownloadOrderResult {
        $context = $this->requestFactory->prepareDownloadContext($context)
            ->setStartDateTime($startDateTime)
            ->setEndDateTime($endDateTime);

        $transaction = $this->downloadTransaction(
            function () use ($context) {
                return $this->requestFactory->createVMK($context);
            }
        );

        return $this->createDownloadOrderResult($transaction, self::FILE_PARSER_FORMAT_TEXT);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsException
     */
    public function STA(
        DateTimeInterface $startDateTime = null,
        DateTimeInterface $endDateTime = null,
        RequestContext $context = null
    ): DownloadOrderResult {
        $context = $this->requestFactory->prepareDownloadContext($context)
            ->setStartDateTime($startDateTime)
            ->setEndDateTime($endDateTime);

        $transaction = $this->downloadTransaction(
            function () use ($context) {
                return $this->requestFactory->createSTA($context);
            }
        );

        return $this->createDownloadOrderResult($transaction, self::FILE_PARSER_FORMAT_TEXT);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsException
     */
    public function BKA(
        DateTimeInterface $startDateTime = null,
        DateTimeInterface $endDateTime = null,
        RequestContext $context = null
    ): DownloadOrderResult {
        $context = $this->requestFactory->prepareDownloadContext($context)
            ->setStartDateTime($startDateTime)
            ->setEndDateTime($endDateTime);

        $transaction = $this->downloadTransaction(
            function () use ($context) {
                return $this->requestFactory->createBKA($context);
            }
        );

        return $this->createDownloadOrderResult($transaction, self::FILE_PARSER_FORMAT_TEXT);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsException
     */
    public function C52(
        DateTimeInterface $startDateTime = null,
        DateTimeInterface $endDateTime = null,
        RequestContext $context = null
    ): DownloadOrderResult {
        $context = $this->requestFactory->prepareDownloadContext($context)
            ->setStartDateTime($startDateTime)
            ->setEndDateTime($endDateTime);

        $transaction = $this->downloadTransaction(
            function () use ($context) {
                return $this->requestFactory->createC52($context);
            }
        );

        return $this->createDownloadOrderResult($transaction, self::FILE_PARSER_FORMAT_ZIP_FILES);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsException
     */
    public function C53(
        DateTimeInterface $startDateTime = null,
        DateTimeInterface $endDateTime = null,
        RequestContext $context = null
    ): DownloadOrderResult {
        $context = $this->requestFactory->prepareDownloadContext($context)
            ->setStartDateTime($startDateTime)
            ->setEndDateTime($endDateTime);

        $transaction = $this->downloadTransaction(
            function () use ($context) {
                return $this->requestFactory->createC53($context);
            }
        );

        return $this->createDownloadOrderResult($transaction, self::FILE_PARSER_FORMAT_ZIP_FILES);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsException
     */
    public function C54(
        DateTimeInterface $startDateTime = null,
        DateTimeInterface $endDateTime = null,
        RequestContext $context = null
    ): DownloadOrderResult {
        $context = $this->requestFactory->prepareDownloadContext($context)
            ->setStartDateTime($startDateTime)
            ->setEndDateTime($endDateTime);

        $transaction = $this->downloadTransaction(
            function () use ($context) {
                return $this->requestFactory->createC54($context);
            }
        );

        return $this->createDownloadOrderResult($transaction, self::FILE_PARSER_FORMAT_ZIP_FILES);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsException
     */
    public function Z52(
        DateTimeInterface $startDateTime = null,
        DateTimeInterface $endDateTime = null,
        RequestContext $context = null
    ): DownloadOrderResult {
        $context = $this->requestFactory->prepareDownloadContext($context)
            ->setStartDateTime($startDateTime)
            ->setEndDateTime($endDateTime);

        $transaction = $this->downloadTransaction(
            function () use ($context) {
                return $this->requestFactory->createZ52($context);
            }
        );

        return $this->createDownloadOrderResult($transaction, self::FILE_PARSER_FORMAT_ZIP_FILES);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsException
     */
    public function Z53(
        DateTimeInterface $startDateTime = null,
        DateTimeInterface $endDateTime = null,
        RequestContext $context = null
    ): DownloadOrderResult {
        $context = $this->requestFactory->prepareDownloadContext($context)
            ->setStartDateTime($startDateTime)
            ->setEndDateTime($endDateTime);

        $transaction = $this->downloadTransaction(
            function () use ($context) {
                return $this->requestFactory->createZ53($context);
            }
        );

        return $this->createDownloadOrderResult($transaction, self::FILE_PARSER_FORMAT_ZIP_FILES);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsException
     */
    public function Z54(
        DateTimeInterface $startDateTime = null,
        DateTimeInterface $endDateTime = null,
        RequestContext $context = null
    ): DownloadOrderResult {
        $context = $this->requestFactory->prepareDownloadContext($context)
            ->setStartDateTime($startDateTime)
            ->setEndDateTime($endDateTime);

        $transaction = $this->downloadTransaction(
            function () use ($context) {
                return $this->requestFactory->createZ54($context);
            }
        );

        return $this->createDownloadOrderResult($transaction, self::FILE_PARSER_FORMAT_ZIP_FILES);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsException
     */
    public function ZSR(
        DateTimeInterface $startDateTime = null,
        DateTimeInterface $endDateTime = null,
        RequestContext $context = null
    ): DownloadOrderResult {
        $context = $this->requestFactory->prepareDownloadContext($context)
            ->setStartDateTime($startDateTime)
            ->setEndDateTime($endDateTime);

        $transaction = $this->downloadTransaction(
            function () use ($context) {
                return $this->requestFactory->createZSR($context);
            }
        );

        return $this->createDownloadOrderResult($transaction, self::FILE_PARSER_FORMAT_ZIP_FILES);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsException
     */
    public function XEK(
        DateTimeInterface $startDateTime = null,
        DateTimeInterface $endDateTime = null,
        RequestContext $context = null
    ): DownloadOrderResult {
        $context = $this->requestFactory->prepareDownloadContext($context)
            ->setStartDateTime($startDateTime)
            ->setEndDateTime($endDateTime);

        $transaction = $this->downloadTransaction(
            function () use ($context) {
                return $this->requestFactory->createXEK($context);
            }
        );

        return $this->createDownloadOrderResult($transaction, self::FILE_PARSER_FORMAT_TEXT);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsException
     */
    public function BTD(
        BTDContext $btdContext,
        DateTimeInterface $startDateTime = null,
        DateTimeInterface $endDateTime = null,
        RequestContext $context = null
    ): DownloadOrderResult {
        $context = $this->requestFactory->prepareStandardContext($context)
            ->setBTDContext($btdContext)
            ->setStartDateTime($startDateTime)
            ->setEndDateTime($endDateTime);

        $transaction = $this->downloadTransaction(
            function () use ($context) {
                return $this->requestFactory->createBTD($context);
            }
        );

        return $this->createDownloadOrderResult($transaction, $btdContext->getParserFormat());
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsException
     */
    public function BTU(
        BTUContext $btuContext,
        OrderDataInterface $orderData,
        RequestContext $context = null
    ): UploadOrderResult {
        $context = $this->requestFactory->prepareStandardContext($context)
            ->setBTUContext($btuContext);

        $transaction = $this->uploadTransaction(
            function (UploadTransaction $transaction) use ($orderData, $context) {
                $transaction->setOrderData($orderData->getContent());
                $transaction->setNumSegments(1);
                $transaction->setDigest($this->cryptService->hash($transaction->getOrderData()));

                return $this->requestFactory->createBTU($transaction, $context);
            }
        );

        return $this->createUploadOrderResult($transaction, $orderData);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsException
     */
    public function FDL(
        FDLContext $fdlContext,
        DateTimeInterface $startDateTime = null,
        DateTimeInterface $endDateTime = null,
        RequestContext $context = null
    ): DownloadOrderResult {
        $context = $this->requestFactory->prepareStandardContext($context)
            ->setFdlContext($fdlContext)
            ->setStartDateTime($startDateTime)
            ->setEndDateTime($endDateTime);

        $transaction = $this->downloadTransaction(
            function () use ($context) {
                return $this->requestFactory->createFDL($context);
            },
            $context->getAckClosure()
        );

        return $this->createDownloadOrderResult($transaction, $fdlContext->getParserFormat());
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsException
     */
    public function FUL(
        FULContext $fulContext,
        OrderDataInterface $orderData,
        RequestContext $context = null
    ): UploadOrderResult {
        $context = $this->requestFactory->prepareStandardContext($context)
            ->setFulContext($fulContext);

        $transaction = $this->uploadTransaction(
            function (UploadTransaction $transaction) use ($orderData, $context) {
                $transaction->setOrderData($orderData->getContent());
                $transaction->setNumSegments(1);
                $transaction->setDigest($this->cryptService->hash($transaction->getOrderData()));

                return $this->requestFactory->createFUL($transaction, $context);
            }
        );

        return $this->createUploadOrderResult($transaction, $orderData);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsResponseException
     * @throws EbicsException
     */
    public function CCT(
        OrderDataInterface $orderData,
        RequestContext $context = null
    ): UploadOrderResult {
        $context = $this->requestFactory->prepareUploadContext($context);
        $transaction = $this->uploadTransaction(
            function (UploadTransaction $transaction) use ($orderData, $context) {
                $transaction->setOrderData($orderData->getContent());
                $transaction->setNumSegments(1);
                $transaction->setDigest($this->cryptService->hash($transaction->getOrderData()));

                return $this->requestFactory->createCCT($transaction, $context);
            }
        );

        return $this->createUploadOrderResult($transaction, $orderData);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsResponseException
     * @throws EbicsException
     */
    public function CDD(
        OrderDataInterface $orderData,
        RequestContext $context = null
    ): UploadOrderResult {
        $context = $this->requestFactory->prepareUploadContext($context);
        $transaction = $this->uploadTransaction(
            function (UploadTransaction $transaction) use ($orderData, $context) {
                $transaction->setOrderData($orderData->getContent());
                $transaction->setNumSegments(1);
                $transaction->setDigest($this->cryptService->hash($transaction->getOrderData()));

                return $this->requestFactory->createCDD($transaction, $context);
            }
        );

        return $this->createUploadOrderResult($transaction, $orderData);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsResponseException
     * @throws EbicsException
     */
    public function CDB(
        OrderDataInterface $orderData,
        RequestContext $context = null
    ): UploadOrderResult {
        $context = $this->requestFactory->prepareUploadContext($context);
        $transaction = $this->uploadTransaction(
            function (UploadTransaction $transaction) use ($orderData, $context) {
                $transaction->setOrderData($orderData->getContent());
                $transaction->setNumSegments(1);
                $transaction->setDigest($this->cryptService->hash($transaction->getOrderData()));

                return $this->requestFactory->createCDB($transaction, $context);
            }
        );

        return $this->createUploadOrderResult($transaction, $orderData);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsResponseException
     * @throws EbicsException
     */
    public function CIP(
        OrderDataInterface $orderData,
        RequestContext $context = null
    ): UploadOrderResult {
        $context = $this->requestFactory->prepareUploadContext($context);
        $transaction = $this->uploadTransaction(
            function (UploadTransaction $transaction) use ($orderData, $context) {
                $transaction->setOrderData($orderData->getContent());
                $transaction->setNumSegments(1);
                $transaction->setDigest($this->cryptService->hash($transaction->getOrderData()));

                return $this->requestFactory->createCIP($transaction, $context);
            }
        );

        return $this->createUploadOrderResult($transaction, $orderData);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsResponseException
     * @throws EbicsException
     */
    public function XE2(
        OrderDataInterface $orderData,
        RequestContext $context = null
    ): UploadOrderResult {
        $context = $this->requestFactory->prepareUploadContext($context);
        $transaction = $this->uploadTransaction(
            function (UploadTransaction $transaction) use ($orderData, $context) {
                $transaction->setOrderData($orderData->getContent());
                $transaction->setNumSegments(1);
                $transaction->setDigest($this->cryptService->hash($transaction->getOrderData()));

                return $this->requestFactory->createXE2($transaction, $context);
            }
        );

        return $this->createUploadOrderResult($transaction, $orderData);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsResponseException
     * @throws EbicsException
     */
    public function XE3(
        OrderDataInterface $orderData,
        RequestContext $context = null
    ): UploadOrderResult {
        $context = $this->requestFactory->prepareUploadContext($context);
        $transaction = $this->uploadTransaction(
            function (UploadTransaction $transaction) use ($orderData, $context) {
                $transaction->setOrderData($orderData->getContent());
                $transaction->setNumSegments(1);
                $transaction->setDigest($this->cryptService->hash($transaction->getOrderData()));

                return $this->requestFactory->createXE3($transaction, $context);
            }
        );

        return $this->createUploadOrderResult($transaction, $orderData);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsResponseException
     * @throws EbicsException
     */
    public function YCT(OrderDataInterface $orderData, RequestContext $context = null): UploadOrderResult
    {
        $context = $this->requestFactory->prepareUploadContext($context);
        $transaction = $this->uploadTransaction(
            function (UploadTransaction $transaction) use ($orderData, $context) {
                $transaction->setOrderData($orderData->getContent());
                $transaction->setNumSegments(1);
                $transaction->setDigest($this->cryptService->hash($transaction->getOrderData()));

                return $this->requestFactory->createYCT($transaction, $context);
            }
        );

        return $this->createUploadOrderResult($transaction, $orderData);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsResponseException
     * @throws EbicsException
     */
    public function HVU(RequestContext $context = null): DownloadOrderResult
    {
        $context = $this->requestFactory->prepareStandardContext($context);
        $transaction = $this->downloadTransaction(
            function () use ($context) {
                return $this->requestFactory->createHVU($context);
            }
        );

        return $this->createDownloadOrderResult($transaction, self::FILE_PARSER_FORMAT_XML);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsResponseException
     * @throws EbicsException
     */
    public function HVZ(RequestContext $context = null): DownloadOrderResult
    {
        $context = $this->requestFactory->prepareStandardContext($context);
        $transaction = $this->downloadTransaction(
            function () use ($context) {
                return $this->requestFactory->createHVZ($context);
            }
        );

        return $this->createDownloadOrderResult($transaction, self::FILE_PARSER_FORMAT_XML);
    }

    /**
     * @inheritDoc
     * @throws EbicsException
     */
    public function HVE(HVEContext $hveContext, RequestContext $context = null): UploadOrderResult
    {
        $context = $this->requestFactory->prepareStandardContext($context)
            ->setHVEContext($hveContext);
        $transaction = $this->uploadTransaction(
            function (UploadTransaction $transaction) use ($context) {
                $transaction->setDigest($context->getHVEContext()->getDigest());
                $transaction->setNumSegments(0);

                return $this->requestFactory->createHVE($transaction, $context);
            }
        );

        return $this->createUploadESResult($transaction, $hveContext->getDigest());
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsResponseException
     * @throws EbicsException
     */
    public function HVD(HVDContext $hvdContext, RequestContext $context = null): DownloadOrderResult
    {
        $context = $this->requestFactory->prepareStandardContext($context)
            ->setHVDContext($hvdContext);
        $transaction = $this->downloadTransaction(
            function () use ($context) {
                return $this->requestFactory->createHVD($context);
            }
        );

        return $this->createDownloadOrderResult($transaction, self::FILE_PARSER_FORMAT_XML);
    }

    /**
     * @inheritDoc
     * @throws Exceptions\EbicsResponseException
     * @throws EbicsException
     */
    public function HVT(HVTContext $hvtContext, RequestContext $context = null): DownloadOrderResult
    {
        $context = $this->requestFactory->prepareStandardContext($context)
            ->setHVTContext($hvtContext);
        $transaction = $this->downloadTransaction(
            function () use ($context) {
                return $this->requestFactory->createHVT($context);
            }
        );

        return $this->createDownloadOrderResult($transaction, self::FILE_PARSER_FORMAT_XML);
    }

    /**
     * Mark download or upload transaction as receipt or not.
     *
     * @throws EbicsException
     * @throws Exceptions\EbicsResponseException
     */
    private function transferReceipt(DownloadTransaction $transaction, bool $acknowledged): void
    {
        $request = $this->requestFactory->createTransferReceipt($transaction->getId(), $acknowledged);
        $response = $this->httpClient->post($this->bank->getUrl(), $request);

        $this->checkH00XReturnCode($request, $response);

        $transaction->setReceipt($response);
    }

    /**
     * Upload transaction segments and mark transaction as transfer.
     *
     * @throws EbicsException
     * @throws Exceptions\EbicsResponseException
     */
    private function transferTransfer(UploadTransaction $uploadTransaction): void
    {
        foreach ($uploadTransaction->getSegments() as $segment) {
            $request = $this->requestFactory->createTransferUpload(
                $segment->getTransactionId(),
                $segment->getTransactionKey(),
                $segment->getOrderData(),
                $segment->getSegmentNumber(),
                $segment->getIsLastSegment()
            );
            $response = $this->httpClient->post($this->bank->getUrl(), $request);
            $this->checkH00XReturnCode($request, $response);

            $segment->setResponse($response);
        }
    }

    /**
     * @param Request $request
     * @param Response $response
     *
     * @throws Exceptions\IncorrectResponseEbicsException
     */
    private function checkH00XReturnCode(Request $request, Response $response): void
    {
        $errorCode = $this->responseHandler->retrieveH00XBodyOrHeaderReturnCode($response);

        if ('000000' === $errorCode) {
            return;
        }

        // For Transaction Done.
        if ('011000' === $errorCode) {
            return;
        }

        $reportText = $this->responseHandler->retrieveH00XReportText($response);
        EbicsExceptionFactory::buildExceptionFromCode($errorCode, $reportText, $request, $response);
    }

    /**
     * @param Request $request
     * @param Response $response
     *
     * @throws Exceptions\IncorrectResponseEbicsException
     */
    private function checkH000ReturnCode(Request $request, Response $response): void
    {
        $errorCode = $this->responseHandler->retrieveH000ReturnCode($response);

        if ('000000' === $errorCode) {
            return;
        }

        $reportText = $this->responseHandler->retrieveH000ReportText($response);
        EbicsExceptionFactory::buildExceptionFromCode($errorCode, $reportText, $request, $response);
    }

    /**
     * Walk by segments to build transaction.
     *
     * @throws EbicsException
     * @throws IncorrectResponseEbicsException
     */
    private function initializeTransaction(callable $requestClosure): InitializationTransaction
    {
        $transaction = $this->transactionFactory->createInitializationTransaction();

        $request = call_user_func($requestClosure);

        $segment = $this->retrieveInitializationSegment($request);
        $transaction->setInitializationSegment($segment);

        return $transaction;
    }

    /**
     * @throws EbicsException
     * @throws IncorrectResponseEbicsException
     */
    private function retrieveInitializationSegment(Request $request): InitializationSegment
    {
        $response = $this->httpClient->post($this->bank->getUrl(), $request);

        $this->checkH00XReturnCode($request, $response);

        return $this->responseHandler->extractInitializationSegment($response, $this->keyring);
    }

    /**
     * Walk by segments to build transaction.
     *
     * @param callable $requestClosure
     * @param callable|null $ackClosure Custom closure to handle acknowledge.
     *
     * @return DownloadTransaction
     * @throws EbicsException
     * @throws EbicsResponseException
     */
    private function downloadTransaction(callable $requestClosure, callable $ackClosure = null): DownloadTransaction
    {
        $transaction = $this->transactionFactory->createDownloadTransaction();

        $segmentNumber = null;
        $isLastSegment = null;

        $request = call_user_func_array($requestClosure, [$segmentNumber, $isLastSegment]);

        $segment = $this->retrieveDownloadSegment($request);
        $transaction->addSegment($segment);

        $lastSegment = $transaction->getLastSegment();

        while (!$lastSegment->isLastSegmentNumber()) {
            $nextSegmentNumber = $lastSegment->getNextSegmentNumber();
            $isLastNextSegmentNumber = $lastSegment->isLastNextSegmentNumber();

            $request = $this->requestFactory->createTransferDownload(
                $lastSegment->getTransactionId(),
                $nextSegmentNumber,
                $isLastNextSegmentNumber
            );

            $segment = $this->retrieveDownloadSegment($request);
            $transaction->addSegment($segment);

            $segment->setNumSegments($lastSegment->getNumSegments());
            $segment->setTransactionKey($lastSegment->getTransactionKey());

            $lastSegment = $segment;
        }

        if (null !== $ackClosure) {
            $acknowledged = call_user_func_array($ackClosure, [$transaction]);
        } else {
            $acknowledged = true;
        }

        $this->transferReceipt($transaction, $acknowledged);

        $orderDataEncoded = $this->bufferFactory->create();
        foreach ($transaction->getSegments() as $segment) {
            $orderDataEncoded->write($segment->getOrderData());
            $segment->setOrderData('');
        }
        $orderDataEncoded->rewind();

        $orderDataDecoded = $this->bufferFactory->create();
        while (!$orderDataEncoded->eof()) {
            $orderDataDecoded->write(base64_decode($orderDataEncoded->read()));
        }
        $orderDataDecoded->rewind();
        unset($orderDataEncoded);

        $orderDataCompressed = $this->bufferFactory->create();
        $this->cryptService->decryptOrderDataCompressed(
            $this->keyring,
            $orderDataDecoded,
            $orderDataCompressed,
            $lastSegment->getTransactionKey()
        );
        unset($orderDataDecoded);

        $orderData = $this->bufferFactory->create();
        $this->zipService->uncompress($orderDataCompressed, $orderData);
        unset($orderDataCompressed);

        $transaction->setOrderData($orderData->readContent());
        unset($orderData);

        return $transaction;
    }

    /**
     * @throws EbicsException
     */
    private function retrieveDownloadSegment(Request $request): DownloadSegment
    {
        $response = $this->httpClient->post($this->bank->getUrl(), $request);

        $this->checkH00XReturnCode($request, $response);

        return $this->responseHandler->extractDownloadSegment($response);
    }

    /**
     * @throws EbicsException
     * @throws EbicsResponseException
     * @throws IncorrectResponseEbicsException
     */
    private function uploadTransaction(callable $requestClosure): UploadTransaction
    {
        $transaction = $this->transactionFactory->createUploadTransaction();
        $transaction->setKey($this->cryptService->generateTransactionKey());

        $request = call_user_func_array($requestClosure, [$transaction]);

        $response = $this->httpClient->post($this->bank->getUrl(), $request);
        $this->checkH00XReturnCode($request, $response);

        $uploadSegment = $this->responseHandler->extractUploadSegment($request, $response);
        $transaction->setInitialization($uploadSegment);

        $segment = $this->segmentFactory->createTransferSegment();
        $segment->setTransactionKey($transaction->getKey());
        $segment->setSegmentNumber(1);
        $segment->setIsLastSegment(true);
        $segment->setNumSegments($transaction->getNumSegments());
        $segment->setOrderData($transaction->getOrderData());
        $segment->setTransactionId($transaction->getInitialization()->getTransactionId());

        if ($segment->getTransactionId()) {
            $transaction->addSegment($segment);
            $transaction->setKey($segment->getTransactionId());
            $this->transferTransfer($transaction);
        }

        return $transaction;
    }

    private function createInitializationOrderResult(InitializationTransaction $transaction): InitializationOrderResult
    {
        $orderResult = $this->orderResultFactory->createInitializationOrderResult();
        $orderResult->setTransaction($transaction);
        $orderResult->setData($transaction->getOrderData());
        $orderResult->setDocument($this->documentFactory->createXml($orderResult->getData()));

        return $orderResult;
    }

    private function createDownloadOrderResult(
        DownloadTransaction $transaction,
        string $parserFormat
    ): DownloadOrderResult {
        $orderResult = $this->orderResultFactory->createDownloadOrderResult();
        $orderResult->setTransaction($transaction);
        $orderResult->setData($transaction->getOrderData());

        switch ($parserFormat) {
            case self::FILE_PARSER_FORMAT_TEXT:
                break;
            case self::FILE_PARSER_FORMAT_XML:
                $orderResult->setDocument($this->documentFactory->createXml($orderResult->getData()));
                break;
            case self::FILE_PARSER_FORMAT_XML_FILES:
                $files = $this->xmlService->extractFilesFromString($orderResult->getData());
                $orderResult->setDataFiles($this->documentFactory->createMultipleXml($files));
                break;
            case self::FILE_PARSER_FORMAT_ZIP_FILES:
                $orderResult->setDataFiles($this->zipService->extractFilesFromString($orderResult->getData()));
                break;
            default:
                throw new LogicException('Incorrect format');
        }

        return $orderResult;
    }

    private function createUploadOrderResult(
        UploadTransaction $transaction,
        OrderDataInterface $document
    ): UploadOrderResult {
        $orderResult = $this->orderResultFactory->createUploadOrderResult();
        $orderResult->setTransaction($transaction);
        $orderResult->setDataDocument($document);
        $orderResult->setData($document->getContent());

        return $orderResult;
    }

    private function createUploadESResult(
        UploadTransaction $transaction,
        string $es
    ): UploadOrderResult {
        $orderResult = $this->orderResultFactory->createUploadOrderResult();
        $orderResult->setTransaction($transaction);
        $orderResult->setData($es);

        return $orderResult;
    }

    /**
     * @inheritDoc
     */
    public function getKeyring(): Keyring
    {
        return $this->keyring;
    }

    /**
     * @inheritDoc
     */
    public function getBank(): Bank
    {
        return $this->bank;
    }

    /**
     * @inheritDoc
     */
    public function getUser(): User
    {
        return $this->user;
    }

    /**
     * Get user signature.
     *
     * @param string $type One of allowed user signature type.
     *
     * @return SignatureInterface
     */
    private function getUserSignature(string $type): SignatureInterface
    {
        switch ($type) {
            case SignatureInterface::TYPE_A:
                $signature = $this->keyring->getUserSignatureA();
                break;
            case SignatureInterface::TYPE_E:
                $signature = $this->keyring->getUserSignatureE();
                break;
            case SignatureInterface::TYPE_X:
                $signature = $this->keyring->getUserSignatureX();
                break;
            default:
                throw new LogicException(sprintf('Type "%s" not allowed', $type));
        }

        return $signature;
    }

    /**
     * Create new signature.
     *
     * @param string $type
     * @param array|null $details
     *
     * @return SignatureInterface
     * @throws PasswordEbicsException
     */
    private function createUserSignature(string $type, array $details = null): SignatureInterface
    {
        switch ($type) {
            case SignatureInterface::TYPE_A:
                if (null === $details) {
                    $keyPair = $this->cryptService->generateKeyPair($this->keyring->getPassword());
                    $certificateGenerator = $this->keyring->getCertificateGenerator();
                } else {
                    $keyPair = $this->cryptService->changePrivateKeyPassword(
                        $details['privatekey'],
                        $details['password'],
                        $this->keyring->getPassword()
                    );
                    $certificateGenerator = new ContentX509Generator();
                    $certificateGenerator->setAContent($details['certificate']);
                }

                $signature = $this->signatureFactory->createSignatureAFromKeys(
                    $keyPair,
                    $this->keyring->getPassword(),
                    $certificateGenerator
                );
                break;
            case SignatureInterface::TYPE_E:
                $signature = $this->signatureFactory->createSignatureEFromKeys(
                    $this->cryptService->generateKeyPair($this->keyring->getPassword()),
                    $this->keyring->getPassword(),
                    $this->keyring->getCertificateGenerator()
                );
                break;
            case SignatureInterface::TYPE_X:
                $signature = $this->signatureFactory->createSignatureXFromKeys(
                    $this->cryptService->generateKeyPair($this->keyring->getPassword()),
                    $this->keyring->getPassword(),
                    $this->keyring->getCertificateGenerator()
                );
                break;
            default:
                throw new LogicException(sprintf('Type "%s" not allowed', $type));
        }

        return $signature;
    }

    /**
     * @inheritDoc
     */
    public function getResponseHandler(): ResponseHandler
    {
        return $this->responseHandler;
    }

    /**
     * @inheritDoc
     * @throws PasswordEbicsException
     */
    public function checkKeyring(): bool
    {
        return $this->cryptService->checkPrivateKey(
            $this->keyring->getUserSignatureX()->getPrivateKey(),
            $this->keyring->getPassword()
        );
    }

    /**
     * @inheritDoc
     * @throws PasswordEbicsException
     */
    public function changeKeyringPassword(string $newPassword): void
    {
        $keyPair = $this->cryptService->changePrivateKeyPassword(
            $this->keyring->getUserSignatureA()->getPrivateKey(),
            $this->keyring->getPassword(),
            $newPassword
        );

        $signature = $this->signatureFactory->createSignatureAFromKeys(
            $keyPair,
            $newPassword,
            $this->keyring->getCertificateGenerator()
        );

        $this->keyring->setUserSignatureA($signature);

        $keyPair = $this->cryptService->changePrivateKeyPassword(
            $this->keyring->getUserSignatureX()->getPrivateKey(),
            $this->keyring->getPassword(),
            $newPassword
        );

        $signature = $this->signatureFactory->createSignatureXFromKeys(
            $keyPair,
            $newPassword,
            $this->keyring->getCertificateGenerator()
        );

        $this->keyring->setUserSignatureX($signature);

        $keyPair = $this->cryptService->changePrivateKeyPassword(
            $this->keyring->getUserSignatureE()->getPrivateKey(),
            $this->keyring->getPassword(),
            $newPassword
        );

        $signature = $this->signatureFactory->createSignatureEFromKeys(
            $keyPair,
            $newPassword,
            $this->keyring->getCertificateGenerator()
        );

        $this->keyring->setUserSignatureE($signature);

        $this->keyring->setPassword($newPassword);
    }

    public function setOrderIdOffset(int $offset): void
    {
        $this->requestFactory->setOrderIdOffset($offset);
    }

    public function getOrderIdOffset(): int
    {
        return $this->requestFactory->getOrderIdOffset();
    }
}
