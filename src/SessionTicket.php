<?php

declare(strict_types=1);

namespace Tourze\TLSSession;

use Tourze\TLSSession\Exception\InvalidArgumentException;

/**
 * TLS会话票据实现
 *
 * 支持TLS 1.2会话票据（RFC 5077）
 */
class SessionTicket
{
    /**
     * 票据密钥名称
     */
    private string $keyName;

    /**
     * 票据IV（初始化向量）
     */
    private string $iv;

    /**
     * 加密的会话状态
     */
    private string $encryptedState;

    /**
     * 票据HMAC
     */
    private string $hmac;

    /**
     * 构造函数
     *
     * @param string $keyName        密钥名称
     * @param string $iv             初始化向量
     * @param string $encryptedState 加密的会话状态
     * @param string $hmac           HMAC
     */
    public function __construct(
        string $keyName = '',
        string $iv = '',
        string $encryptedState = '',
        string $hmac = '',
    ) {
        $this->keyName = $keyName;
        $this->iv = $iv;
        $this->encryptedState = $encryptedState;
        $this->hmac = $hmac;
    }

    /**
     * 获取票据密钥名称
     *
     * @return string 密钥名称
     */
    public function getKeyName(): string
    {
        return $this->keyName;
    }

    /**
     * 设置票据密钥名称
     *
     * @param string $keyName 密钥名称
     */
    public function setKeyName(string $keyName): void
    {
        $this->keyName = $keyName;
    }

    /**
     * 获取票据IV
     *
     * @return string IV
     */
    public function getIV(): string
    {
        return $this->iv;
    }

    /**
     * 设置票据IV
     *
     * @param string $iv IV
     */
    public function setIV(string $iv): void
    {
        $this->iv = $iv;
    }

    /**
     * 获取加密的会话状态
     *
     * @return string 加密的会话状态
     */
    public function getEncryptedState(): string
    {
        return $this->encryptedState;
    }

    /**
     * 设置加密的会话状态
     *
     * @param string $encryptedState 加密的会话状态
     */
    public function setEncryptedState(string $encryptedState): void
    {
        $this->encryptedState = $encryptedState;
    }

    /**
     * 获取票据HMAC
     *
     * @return string HMAC
     */
    public function getHMAC(): string
    {
        return $this->hmac;
    }

    /**
     * 设置票据HMAC
     *
     * @param string $hmac HMAC
     */
    public function setHMAC(string $hmac): void
    {
        $this->hmac = $hmac;
    }

    /**
     * 将票据序列化为二进制数据
     *
     * @return string 序列化的票据数据
     */
    public function encode(): string
    {
        $result = '';

        // 密钥名称 (16字节)
        $result .= str_pad($this->keyName, 16, "\0", STR_PAD_RIGHT);

        // IV (16字节)
        $result .= $this->iv;

        // 加密状态长度 (2字节)
        $stateLength = strlen($this->encryptedState);
        $result .= chr(($stateLength >> 8) & 0xFF) . chr($stateLength & 0xFF);

        // 加密状态
        $result .= $this->encryptedState;

        // HMAC (通常32字节，使用SHA-256)
        $result .= $this->hmac;

        return $result;
    }

    /**
     * 从二进制数据解码票据
     *
     * @param string $data 二进制票据数据
     *
     * @return self 票据对象
     *
     * @throws InvalidArgumentException 如果数据格式不正确
     */
    public static function decode(string $data): self
    {
        if (strlen($data) < 36) { // 16 (keyName) + 16 (IV) + 2 (length) + 2 (至少状态数据)
            throw new InvalidArgumentException('票据数据太短');
        }

        $offset = 0;

        // 密钥名称 (16字节)
        $keyName = substr($data, $offset, 16);
        $offset += 16;

        // IV (16字节)
        $iv = substr($data, $offset, 16);
        $offset += 16;

        // 加密状态长度 (2字节)
        $stateLength = (ord($data[$offset]) << 8) | ord($data[$offset + 1]);
        $offset += 2;

        if (strlen($data) < $offset + $stateLength + 32) { // +32 for HMAC
            throw new InvalidArgumentException('票据数据长度不正确');
        }

        // 加密状态
        $encryptedState = substr($data, $offset, $stateLength);
        $offset += $stateLength;

        // HMAC (使用SHA-256，32字节)
        $hmac = substr($data, $offset, 32);

        return new self($keyName, $iv, $encryptedState, $hmac);
    }
}
