<?php

declare(strict_types=1);

namespace Tourze\TLSSession;

/**
 * TLS 1.3 PSK会话实现
 *
 * 用于TLS 1.3中的PSK会话恢复
 */
class TLS13PSKSession extends TLSSession
{
    /**
     * PSK身份标识符
     */
    private string $pskIdentity;

    /**
     * 票据年龄添加值
     */
    private int $ticketAgeAdd;

    /**
     * 票据随机数
     */
    private string $ticketNonce;

    /**
     * 恢复主密钥
     */
    private string $resumptionMasterSecret;

    /**
     * 是否允许早期数据
     */
    private bool $earlyDataAllowed = false;

    /**
     * 早期数据最大大小
     */
    private int $maxEarlyDataSize = 0;

    /**
     * 构造函数
     */
    public function __construct(
        string $sessionId = '',
        int $cipherSuite = 0,
        string $masterSecret = '',
        int $timestamp = 0,
        string $pskIdentity = '',
        int $ticketAgeAdd = 0,
        string $ticketNonce = '',
        string $resumptionMasterSecret = '',
    ) {
        parent::__construct(
            $sessionId,
            $masterSecret,
            (string) $cipherSuite,
            0x0304, // TLS 1.3
            $timestamp
        );

        $this->pskIdentity = $pskIdentity;
        $this->ticketAgeAdd = $ticketAgeAdd;
        $this->ticketNonce = $ticketNonce;
        $this->resumptionMasterSecret = $resumptionMasterSecret;
    }

    /**
     * 获取PSK身份
     *
     * @return string PSK身份
     */
    public function getPskIdentity(): string
    {
        return $this->pskIdentity;
    }

    /**
     * 设置PSK身份
     *
     * @param string $pskIdentity PSK身份
     */
    public function setPskIdentity(string $pskIdentity): void
    {
        $this->pskIdentity = $pskIdentity;
    }

    /**
     * 获取票据年龄添加值
     *
     * @return int 票据年龄添加值
     */
    public function getTicketAgeAdd(): int
    {
        return $this->ticketAgeAdd;
    }

    /**
     * 设置票据年龄添加值
     *
     * @param int $ticketAgeAdd 票据年龄添加值
     */
    public function setTicketAgeAdd(int $ticketAgeAdd): void
    {
        $this->ticketAgeAdd = $ticketAgeAdd;
    }

    /**
     * 获取票据随机数
     *
     * @return string 票据随机数
     */
    public function getTicketNonce(): string
    {
        return $this->ticketNonce;
    }

    /**
     * 设置票据随机数
     *
     * @param string $ticketNonce 票据随机数
     */
    public function setTicketNonce(string $ticketNonce): void
    {
        $this->ticketNonce = $ticketNonce;
    }

    /**
     * 获取恢复主密钥
     *
     * @return string 恢复主密钥
     */
    public function getResumptionMasterSecret(): string
    {
        return $this->resumptionMasterSecret;
    }

    /**
     * 设置恢复主密钥
     *
     * @param string $resumptionMasterSecret 恢复主密钥
     */
    public function setResumptionMasterSecret(string $resumptionMasterSecret): void
    {
        $this->resumptionMasterSecret = $resumptionMasterSecret;
    }

    /**
     * 是否允许早期数据
     *
     * @return bool 是否允许
     */
    public function isEarlyDataAllowed(): bool
    {
        return $this->earlyDataAllowed;
    }

    /**
     * 设置是否允许早期数据
     *
     * @param bool $allowed 是否允许
     */
    public function setEarlyDataAllowed(bool $allowed): void
    {
        $this->earlyDataAllowed = $allowed;
    }

    /**
     * 获取早期数据最大大小
     *
     * @return int 最大大小（字节）
     */
    public function getMaxEarlyDataSize(): int
    {
        return $this->maxEarlyDataSize;
    }

    /**
     * 设置早期数据最大大小
     *
     * @param int $maxSize 最大大小（字节）
     */
    public function setMaxEarlyDataSize(int $maxSize): void
    {
        $this->maxEarlyDataSize = $maxSize;
        $this->earlyDataAllowed = ($maxSize > 0);
    }
}
