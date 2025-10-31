<?php

declare(strict_types=1);

namespace Tourze\TLSSession;

use Tourze\TLSSession\Exception\InvalidArgumentException;

/**
 * TLS会话抽象基类
 */
abstract class TLSSession implements SessionInterface
{
    /**
     * 会话ID
     */
    private string $sessionId;

    /**
     * 加密套件
     */
    private string $cipherSuite;

    /**
     * TLS版本
     */
    private int $tlsVersion;

    /**
     * 主密钥
     */
    private string $masterSecret;

    /**
     * 创建时间
     */
    private int $creationTime;

    /**
     * 会话有效期（秒）
     */
    private int $lifetime = 3600; // 默认1小时

    /**
     * 构造函数
     *
     * @param string $sessionId    会话ID
     * @param string $masterSecret 主密钥
     * @param string $cipherSuite  加密套件
     * @param int    $tlsVersion   TLS版本
     * @param int    $timestamp    创建时间戳
     */
    public function __construct(
        string $sessionId = '',
        string $masterSecret = '',
        string $cipherSuite = '',
        int $tlsVersion = 0,
        int $timestamp = 0,
    ) {
        $this->sessionId = $sessionId;
        $this->masterSecret = $masterSecret;
        $this->cipherSuite = $cipherSuite;
        $this->tlsVersion = $tlsVersion;
        $this->creationTime = 0 !== $timestamp ? $timestamp : time();
    }

    public function getSessionId(): string
    {
        return $this->sessionId;
    }

    public function setSessionId(string $sessionId): void
    {
        if (strlen($sessionId) > 32) {
            throw new InvalidArgumentException('Session ID cannot exceed 32 bytes');
        }

        $this->sessionId = $sessionId;
    }

    public function getCipherSuite(): string
    {
        return $this->cipherSuite;
    }

    public function setCipherSuite(string $cipherSuite): void
    {
        $this->cipherSuite = $cipherSuite;
    }

    /**
     * 获取TLS版本
     */
    public function getTlsVersion(): int
    {
        return $this->tlsVersion;
    }

    /**
     * 设置TLS版本
     */
    public function setTlsVersion(int $tlsVersion): void
    {
        $this->tlsVersion = $tlsVersion;
    }

    public function getMasterSecret(): string
    {
        return $this->masterSecret;
    }

    public function setMasterSecret(string $masterSecret): void
    {
        $this->masterSecret = $masterSecret;
    }

    public function getCreationTime(): int
    {
        return $this->creationTime;
    }

    public function setCreationTime(int $creationTime): void
    {
        $this->creationTime = $creationTime;
    }

    /**
     * 获取会话有效期
     *
     * @return int 有效期（秒）
     */
    public function getLifetime(): int
    {
        return $this->lifetime;
    }

    /**
     * 设置会话有效期
     *
     * @param int $lifetime 有效期（秒）
     */
    public function setLifetime(int $lifetime): void
    {
        $this->lifetime = $lifetime;
    }

    /**
     * 获取时间戳
     */
    public function getTimestamp(): int
    {
        return $this->creationTime;
    }

    public function isValid(int $currentTime = 0): bool
    {
        $currentTime = 0 !== $currentTime ? $currentTime : time();

        return $currentTime < ($this->creationTime + $this->lifetime);
    }
}
