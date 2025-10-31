<?php

declare(strict_types=1);

namespace Tourze\TLSSession\KeyDerivation;

/**
 * 会话密钥数据结构
 */
class SessionKeys
{
    /**
     * 构造函数
     *
     * @param string      $clientWriteKey 客户端写入密钥
     * @param string      $serverWriteKey 服务器写入密钥
     * @param string      $clientWriteIV  客户端写入IV
     * @param string      $serverWriteIV  服务器写入IV
     * @param string|null $clientMACKey   客户端MAC密钥(CBC模式需要)
     * @param string|null $serverMACKey   服务器MAC密钥(CBC模式需要)
     */
    public function __construct(
        public readonly string $clientWriteKey,
        public readonly string $serverWriteKey,
        public readonly string $clientWriteIV,
        public readonly string $serverWriteIV,
        public readonly ?string $clientMACKey = null,
        public readonly ?string $serverMACKey = null,
    ) {
    }

    /**
     * 创建客户端密钥集合(客户端视角)
     *
     * @return array{key: string, iv: string, mac_key: string|null} 包含写入密钥、IV和MAC密钥的数组
     */
    public function clientKeys(): array
    {
        return [
            'key' => $this->clientWriteKey,
            'iv' => $this->clientWriteIV,
            'mac_key' => $this->clientMACKey,
        ];
    }

    /**
     * 创建服务器密钥集合(客户端视角)
     *
     * @return array{key: string, iv: string, mac_key: string|null} 包含写入密钥、IV和MAC密钥的数组
     */
    public function serverKeys(): array
    {
        return [
            'key' => $this->serverWriteKey,
            'iv' => $this->serverWriteIV,
            'mac_key' => $this->serverMACKey,
        ];
    }

    /**
     * 创建写入密钥集合(服务器视角)
     *
     * @return array{key: string, iv: string, mac_key: string|null} 包含写入密钥、IV和MAC密钥的数组
     */
    public function writeKeys(): array
    {
        return [
            'key' => $this->serverWriteKey,
            'iv' => $this->serverWriteIV,
            'mac_key' => $this->serverMACKey,
        ];
    }

    /**
     * 创建读取密钥集合(服务器视角)
     *
     * @return array{key: string, iv: string, mac_key: string|null} 包含读取密钥、IV和MAC密钥的数组
     */
    public function readKeys(): array
    {
        return [
            'key' => $this->clientWriteKey,
            'iv' => $this->clientWriteIV,
            'mac_key' => $this->clientMACKey,
        ];
    }
}
