<?php

namespace AndrewSvirin\Ebics\Factories;

use AndrewSvirin\Ebics\Builders\Request\BodyBuilder;
use AndrewSvirin\Ebics\Builders\Request\DataEncryptionInfoBuilder;
use AndrewSvirin\Ebics\Builders\Request\DataTransferBuilder;
use AndrewSvirin\Ebics\Builders\Request\HeaderBuilder;
use AndrewSvirin\Ebics\Builders\Request\MutableBuilder;
use AndrewSvirin\Ebics\Builders\Request\OrderDetailsBuilder;
use AndrewSvirin\Ebics\Builders\Request\RequestBuilder;
use AndrewSvirin\Ebics\Builders\Request\StaticBuilder;
use AndrewSvirin\Ebics\Builders\Request\XmlBuilder;
use AndrewSvirin\Ebics\Builders\Request\XmlBuilderV3;
use AndrewSvirin\Ebics\Contexts\BTDContext;
use AndrewSvirin\Ebics\Contexts\BTUContext;
use AndrewSvirin\Ebics\Contexts\RequestContext;
use AndrewSvirin\Ebics\Exceptions\EbicsException;
use AndrewSvirin\Ebics\Handlers\AuthSignatureHandlerV3;
use AndrewSvirin\Ebics\Handlers\OrderDataHandlerV3;
use AndrewSvirin\Ebics\Handlers\UserSignatureHandlerV3;
use AndrewSvirin\Ebics\Models\Bank;
use AndrewSvirin\Ebics\Models\Http\Request;
use AndrewSvirin\Ebics\Models\Keyring;
use AndrewSvirin\Ebics\Models\UploadTransaction;
use AndrewSvirin\Ebics\Models\User;
use AndrewSvirin\Ebics\Models\UserSignature;
use AndrewSvirin\Ebics\Services\DigestResolverV3;
use DateTime;
use DateTimeInterface;
use LogicException;

/**
 * Ebics 3.0 RequestFactory.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
final class RequestFactoryV3 extends RequestFactory
{
    public function __construct(Bank $bank, User $user, Keyring $keyring)
    {
        $this->authSignatureHandler = new AuthSignatureHandlerV3($keyring);
        $this->userSignatureHandler = new UserSignatureHandlerV3($user, $keyring);
        $this->orderDataHandler = new OrderDataHandlerV3($user, $keyring);
        $this->digestResolver = new DigestResolverV3();
        parent::__construct($bank, $user, $keyring);
    }

    protected function createRequestBuilderInstance(): RequestBuilder
    {
        return $this->requestBuilder
            ->createInstance(function (Request $request) {
                return new XmlBuilderV3($request);
            });
    }

    protected function addOrderType(
        OrderDetailsBuilder $orderDetailsBuilder,
        string $orderType,
        bool $withES = false
    ): OrderDetailsBuilder {
        return $orderDetailsBuilder->addAdminOrderType($orderType);
    }

    /**
     * @throws EbicsException
     */
    public function createBTD(
        BTDContext $btdContext,
        ?DateTimeInterface $startDateTime,
        ?DateTimeInterface $endDateTime,
        ?DateTimeInterface $dateTime
    ): Request {
        $context = (new RequestContext())
            ->setBank($this->bank)
            ->setUser($this->user)
            ->setKeyring($this->keyring)
            ->setBTDContext($btdContext)
            ->setStartDateTime($startDateTime)
            ->setEndDateTime($endDateTime)
            ->setDateTime($dateTime ?? new DateTime());

        $request = $this
            ->createRequestBuilderInstance()
            ->addContainerSecured(function (XmlBuilder $builder) use ($context) {
                $builder->addHeader(function (HeaderBuilder $builder) use ($context) {
                    $builder->addStatic(function (StaticBuilder $builder) use ($context) {
                        $builder
                            ->addHostId($context->getBank()->getHostId())
                            ->addRandomNonce()
                            ->addTimestamp($context->getDateTime())
                            ->addPartnerId($context->getUser()->getPartnerId())
                            ->addUserId($context->getUser()->getUserId())
                            ->addProduct('Ebics client PHP', 'de')
                            ->addOrderDetails(function (OrderDetailsBuilder $orderDetailsBuilder) use ($context) {
                                $this
                                    ->addOrderType($orderDetailsBuilder, 'BTD')
                                    ->addBTDOrderParams(
                                        $context->getBTDContext(),
                                        $context->getStartDateTime(),
                                        $context->getEndDateTime()
                                    );
                            })
                            ->addBankPubKeyDigests(
                                $context->getKeyring()->getBankSignatureXVersion(),
                                $this->digestResolver->signDigest($context->getKeyring()->getBankSignatureX()),
                                $context->getKeyring()->getBankSignatureEVersion(),
                                $this->digestResolver->signDigest($context->getKeyring()->getBankSignatureE())
                            )
                            ->addSecurityMedium(StaticBuilder::SECURITY_MEDIUM_0000);
                    })->addMutable(function (MutableBuilder $builder) {
                        $builder
                            ->addTransactionPhase(MutableBuilder::PHASE_INITIALIZATION);
                    });
                })->addBody();
            })
            ->popInstance();

        $this->authSignatureHandler->handle($request);

        return $request;
    }

    public function createBTU(
        UploadTransaction $transaction,
        BTUContext $btuContext,
        ?DateTimeInterface $dateTime
    ): Request {
        $signatureData = new UserSignature();

        $this->userSignatureHandler->handle($signatureData, $transaction->getDigest());

        $signatureVersion = $this->keyring->getUserSignatureAVersion();
        $dataDigest = $this->cryptService->sign(
            $this->keyring->getUserSignatureA()->getPrivateKey(),
            $this->keyring->getPassword(),
            $this->keyring->getUserSignatureAVersion(),
            $transaction->getDigest()
        );

        $context = (new RequestContext())
            ->setBank($this->bank)
            ->setUser($this->user)
            ->setKeyring($this->keyring)
            ->setDateTime($dateTime ?? new DateTime())
            ->setBTUContext($btuContext)
            ->setTransactionKey($transaction->getKey())
            ->setNumSegments($transaction->getNumSegments())
            ->setSignatureData($signatureData)
            ->setSignatureVersion($signatureVersion)
            ->setDataDigest($dataDigest);

        $request = $this
            ->createRequestBuilderInstance()
            ->addContainerSecured(function (XmlBuilder $builder) use ($context) {
                $builder->addHeader(function (HeaderBuilder $builder) use ($context) {
                    $builder->addStatic(function (StaticBuilder $builder) use ($context) {
                        $builder
                            ->addHostId($context->getBank()->getHostId())
                            ->addRandomNonce()
                            ->addTimestamp($context->getDateTime())
                            ->addPartnerId($context->getUser()->getPartnerId())
                            ->addUserId($context->getUser()->getUserId())
                            ->addProduct('Ebics client PHP', 'de')
                            ->addOrderDetails(function (OrderDetailsBuilder $orderDetailsBuilder) use ($context) {
                                $this
                                    ->addOrderType($orderDetailsBuilder, 'BTU')
                                    ->addBTUOrderParams($context->getBTUContext());
                            })
                            ->addBankPubKeyDigests(
                                $context->getKeyring()->getBankSignatureXVersion(),
                                $this->digestResolver->signDigest($context->getKeyring()->getBankSignatureX()),
                                $context->getKeyring()->getBankSignatureEVersion(),
                                $this->digestResolver->signDigest($context->getKeyring()->getBankSignatureE())
                            )
                            ->addSecurityMedium(StaticBuilder::SECURITY_MEDIUM_0000)
                            ->addNumSegments($context->getNumSegments());
                    })->addMutable(function (MutableBuilder $builder) {
                        $builder->addTransactionPhase(MutableBuilder::PHASE_INITIALIZATION);
                    });
                })->addBody(function (BodyBuilder $builder) use ($context) {
                    $builder->addDataTransfer(function (DataTransferBuilder $builder) use ($context) {
                        $builder
                            ->addDataEncryptionInfo(function (DataEncryptionInfoBuilder $builder) use ($context) {
                                $builder
                                    ->addEncryptionPubKeyDigest($context->getKeyring())
                                    ->addTransactionKey($context->getTransactionKey(), $context->getKeyring());
                            })
                            ->addSignatureData($context->getSignatureData(), $context->getTransactionKey())
                            ->addDataDigest(
                                $context->getSignatureVersion(),
                                $context->getDataDigest()
                            )
                            ->addAdditionalOrderInfo();
                    });
                });
            })
            ->popInstance();

        $this->authSignatureHandler->handle($request);

        return $request;
    }

    public function createVMK(
        ?DateTimeInterface $startDateTime,
        ?DateTimeInterface $endDateTime,
        bool $withES,
        ?DateTimeInterface $dateTime
    ): Request {
        throw new LogicException('Method not implemented yet for EBICS 3.0');
    }

    public function createSTA(
        ?DateTimeInterface $startDateTime,
        ?DateTimeInterface $endDateTime,
        bool $withES,
        ?DateTimeInterface $dateTime
    ): Request {
        throw new LogicException('Method not implemented yet for EBICS 3.0');
    }

    public function createC52(
        ?DateTimeInterface $startDateTime,
        ?DateTimeInterface $endDateTime,
        bool $withES,
        ?DateTimeInterface $dateTime
    ): Request {
        throw new LogicException('Method not implemented yet for EBICS 3.0');
    }

    public function createC53(
        ?DateTimeInterface $startDateTime,
        ?DateTimeInterface $endDateTime,
        bool $withES,
        ?DateTimeInterface $dateTime
    ): Request {
        $btdContext = new BTDContext();
        $btdContext->setServiceName('EOP');
        $btdContext->setScope('DE');
        $btdContext->setMsgName('camt.053');
        $btdContext->setContainerType('ZIP');

        return $this->createBTD($btdContext, $startDateTime, $endDateTime, $dateTime);
    }

    public function createC54(
        ?DateTimeInterface $startDateTime,
        ?DateTimeInterface $endDateTime,
        bool $withES,
        ?DateTimeInterface $dateTime
    ): Request {
        throw new LogicException('Method not implemented yet for EBICS 3.0');
    }

    public function createZ52(
        ?DateTimeInterface $startDateTime,
        ?DateTimeInterface $endDateTime,
        bool $withES,
        ?DateTimeInterface $dateTime
    ): Request {
        throw new LogicException('Method not implemented yet for EBICS 3.0');
    }

    public function createZ53(
        ?DateTimeInterface $startDateTime,
        ?DateTimeInterface $endDateTime,
        bool $withES,
        ?DateTimeInterface $dateTime
    ): Request {
        throw new LogicException('Method not implemented yet for EBICS 3.0');
    }

    /**
     * @throws EbicsException
     */
    public function createZ54(
        ?DateTimeInterface $startDateTime,
        ?DateTimeInterface $endDateTime,
        bool $withES,
        ?DateTimeInterface $dateTime
    ): Request {
        $btdContext = new BTDContext();
        $btdContext->setServiceName('REP');
        $btdContext->setScope('CH');
        $btdContext->setMsgName('camt.054');
        $btdContext->setMsgNameVersion('04');
        $btdContext->setContainerType('ZIP');
        $btdContext->setServiceOption('XQRR');

        return $this->createBTD($btdContext, $startDateTime, $endDateTime, $dateTime);
    }

    /**
     * @throws EbicsException
     */
    public function createZSR(
        ?DateTimeInterface $startDateTime,
        ?DateTimeInterface $endDateTime,
        ?DateTimeInterface $dateTime
    ): Request {
        $btdContext = new BTDContext();
        $btdContext->setServiceName('PSR');
        $btdContext->setScope('BIL');
        $btdContext->setMsgName('pain.002');
        $btdContext->setContainerType('ZIP');

        return $this->createBTD($btdContext, $startDateTime, $endDateTime, $dateTime);
    }

    /**
     * @throws EbicsException
     */
    public function createXEK(
        ?DateTimeInterface $startDateTime,
        ?DateTimeInterface $endDateTime,
        ?DateTimeInterface $dateTime
    ): Request {
        $btdContext = new BTDContext();
        $btdContext->setServiceName('EOP');
        $btdContext->setScope('AT');
        $btdContext->setMsgName('pdf');
        $btdContext->setContainerType('ZIP');

        return $this->createBTD($btdContext, $startDateTime, $endDateTime, $dateTime);
    }

    public function createCCT(UploadTransaction $transaction, bool $withES, ?DateTimeInterface $dateTime): Request
    {
        throw new LogicException('Method not implemented yet for EBICS 3.0');
    }

    public function createCDD(UploadTransaction $transaction, bool $withES, ?DateTimeInterface $dateTime): Request
    {
        throw new LogicException('Method not implemented yet for EBICS 3.0');
    }

    public function createCDB(UploadTransaction $transaction, bool $withES, ?DateTimeInterface $dateTime): Request
    {
        throw new LogicException('Method not implemented yet for EBICS 3.0');
    }

    public function createCIP(UploadTransaction $transaction, bool $withES, ?DateTimeInterface $dateTime): Request
    {
        throw new LogicException('Method not implemented yet for EBICS 3.0');
    }

    public function createXE2(UploadTransaction $transaction, bool $withES, ?DateTimeInterface $dateTime): Request
    {
        throw new LogicException('Method not implemented yet for EBICS 3.0');
    }

    public function createXE3(UploadTransaction $transaction, bool $withES, ?DateTimeInterface $dateTime): Request
    {
        $btuContext = new BTUContext();
        $btuContext->setServiceName('SDD');
        $btuContext->setScope('CH');
        $btuContext->setMsgName('pain.008');
        $btuContext->setMsgNameVersion('02');
        $btuContext->setFileName('xe3.pain008.xml');

        return $this->createBTU($transaction, $btuContext, $dateTime);
    }

    public function createYCT(UploadTransaction $transaction, ?DateTimeInterface $dateTime): Request
    {
        $btuContext = new BTUContext();
        $btuContext->setServiceName('MCT');
        $btuContext->setScope('BIL');
        $btuContext->setMsgName('pain.001');
        $btuContext->setFileName('yct.pain001.xml');

        return $this->createBTU($transaction, $btuContext, $dateTime);
    }
}
