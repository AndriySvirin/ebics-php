<?php

namespace EbicsApi\Ebics\Contexts;

use DateTime;
use DateTimeInterface;
use EbicsApi\Ebics\Contracts\SignatureDataInterface;
use EbicsApi\Ebics\Models\Bank;
use EbicsApi\Ebics\Models\Keyring;
use EbicsApi\Ebics\Models\User;

/**
 * Class RequestContext context container for @see \EbicsApi\Ebics\Factories\RequestFactory
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
final class RequestContext
{
    /**
     * Request have both ES and OrderData
     */
    private bool $withES;
    private bool $onlyES;

    /**
     * @var callable|null $ackClosure Custom closure to handle download acknowledge.
     */
    private $ackClosure = null;

    private string $orderType;
    private Bank $bank;
    private User $user;
    private Keyring $keyring;
    private DateTimeInterface $dateTime;
    private ?DateTimeInterface $startDateTime;
    private ?DateTimeInterface $endDateTime;
    private ?FDLContext $fdlContext = null;
    private ?FULContext $fulContext = null;
    private string $receiptCode;
    private ?int $segmentNumber;
    private ?bool $isLastSegment;
    private string $transactionId;
    private string $transactionKey;
    private int $numSegments;
    private string $orderData;
    private SignatureDataInterface $signatureData;
    private string $dataDigest;
    private string $signatureVersion;
    private ?BTDContext $btdContext = null;
    private ?BTUContext $btuContext = null;
    private HVEContext $hveContext;
    private HVDContext $hvdContext;
    private HVTContext $hvtContext;
    private string $product;
    private string $language;

    public function __construct()
    {
        $this->dateTime = new DateTime();
        $this->withES = false;
        $this->onlyES = false;
        $this->product = 'Ebics client PHP';
        $this->language = 'de';
    }

    public function setBank(Bank $bank): RequestContext
    {
        $this->bank = $bank;

        return $this;
    }

    public function getBank(): Bank
    {
        return $this->bank;
    }

    public function setUser(User $user): RequestContext
    {
        $this->user = $user;

        return $this;
    }

    public function getUser(): User
    {
        return $this->user;
    }

    public function setKeyring(Keyring $keyring): RequestContext
    {
        $this->keyring = $keyring;

        return $this;
    }

    public function getKeyring(): Keyring
    {
        return $this->keyring;
    }

    public function setDateTime(DateTimeInterface $dateTime): RequestContext
    {
        $this->dateTime = $dateTime;

        return $this;
    }

    public function getDateTime(): DateTimeInterface
    {
        return $this->dateTime;
    }

    public function setStartDateTime(?DateTimeInterface $startDateTime): RequestContext
    {
        $this->startDateTime = $startDateTime;

        return $this;
    }

    public function getStartDateTime(): ?DateTimeInterface
    {
        return $this->startDateTime;
    }

    public function setEndDateTime(?DateTimeInterface $endDateTime): RequestContext
    {
        $this->endDateTime = $endDateTime;

        return $this;
    }

    public function getEndDateTime(): ?DateTimeInterface
    {
        return $this->endDateTime;
    }

    public function setWithES(bool $withES): RequestContext
    {
        $this->withES = $withES;

        return $this;
    }

    public function getWithES(): bool
    {
        return $this->withES;
    }

    public function setFdlContext(FDLContext $fdlContext): RequestContext
    {
        $this->fdlContext = $fdlContext;

        return $this;
    }

    public function getFdlContext(): ?FDLContext
    {
        return $this->fdlContext;
    }

    public function setFulContext(FULContext $fdlContext): RequestContext
    {
        $this->fulContext = $fdlContext;

        return $this;
    }

    public function getFulContext(): ?FULContext
    {
        return $this->fulContext;
    }


    public function setReceiptCode(string $receiptCode): RequestContext
    {
        $this->receiptCode = $receiptCode;

        return $this;
    }

    public function getReceiptCode(): string
    {
        return $this->receiptCode;
    }

    public function setSegmentNumber(?int $segmentNumber): RequestContext
    {
        $this->segmentNumber = $segmentNumber;

        return $this;
    }

    public function getSegmentNumber(): ?int
    {
        return $this->segmentNumber;
    }

    public function setIsLastSegment(?bool $isLastSegment): RequestContext
    {
        $this->isLastSegment = $isLastSegment;

        return $this;
    }

    public function getIsLastSegment(): ?bool
    {
        return $this->isLastSegment;
    }

    public function setTransactionId(string $transactionId): RequestContext
    {
        $this->transactionId = $transactionId;

        return $this;
    }

    public function getTransactionId(): string
    {
        return $this->transactionId;
    }

    public function setTransactionKey(string $transactionKey): RequestContext
    {
        $this->transactionKey = $transactionKey;

        return $this;
    }

    public function getTransactionKey(): string
    {
        return $this->transactionKey;
    }

    public function setNumSegments(int $numSegments): RequestContext
    {
        $this->numSegments = $numSegments;

        return $this;
    }

    public function getNumSegments(): int
    {
        return $this->numSegments;
    }

    public function setOrderData(string $orderData): RequestContext
    {
        $this->orderData = $orderData;

        return $this;
    }

    public function getOrderData(): string
    {
        return $this->orderData;
    }

    public function setSignatureData(SignatureDataInterface $signatureData): RequestContext
    {
        $this->signatureData = $signatureData;

        return $this;
    }

    public function getSignatureData(): SignatureDataInterface
    {
        return $this->signatureData;
    }

    public function setBTDContext(BTDContext $btdContext): RequestContext
    {
        $this->btdContext = $btdContext;

        return $this;
    }

    public function getBTDContext(): ?BTDContext
    {
        return $this->btdContext;
    }

    public function setHVEContext(HVEContext $hveContext): RequestContext
    {
        $this->hveContext = $hveContext;

        return $this;
    }

    public function getHVEContext(): HVEContext
    {
        return $this->hveContext;
    }

    public function setHVDContext(HVDContext $hvdContext): RequestContext
    {
        $this->hvdContext = $hvdContext;

        return $this;
    }

    public function getHVDContext(): HVDContext
    {
        return $this->hvdContext;
    }

    public function setHVTContext(HVTContext $hvtContext): RequestContext
    {
        $this->hvtContext = $hvtContext;

        return $this;
    }

    public function getHVTContext(): HVTContext
    {
        return $this->hvtContext;
    }

    public function setBTUContext(BTUContext $btuContext): RequestContext
    {
        $this->btuContext = $btuContext;

        return $this;
    }

    public function getBTUContext(): ?BTUContext
    {
        return $this->btuContext;
    }

    public function setDataDigest(?string $dataDigest): RequestContext
    {
        $this->dataDigest = $dataDigest;

        return $this;
    }

    public function getDataDigest(): ?string
    {
        return $this->dataDigest;
    }

    public function setSignatureVersion(string $signatureVersion): RequestContext
    {
        $this->signatureVersion = $signatureVersion;

        return $this;
    }

    public function getSignatureVersion(): string
    {
        return $this->signatureVersion;
    }

    public function getAckClosure(): ?callable
    {
        return $this->ackClosure;
    }

    public function setAckClosure(?callable $ackClosure): void
    {
        $this->ackClosure = $ackClosure;
    }

    public function setOnlyES(bool $onlyES): void
    {
        $this->onlyES = $onlyES;
    }

    public function isOnlyES(): bool
    {
        return $this->onlyES;
    }

    public function getProduct(): string
    {
        return $this->product;
    }

    public function getLanguage(): string
    {
        return $this->language;
    }

    public function getOrderType(): string
    {
        return $this->orderType;
    }

    public function setOrderType(string $orderType): RequestContext
    {
        $this->orderType = $orderType;

        return $this;
    }
}
