<?php

declare(strict_types=1);

namespace Tourze\TLSSession\KeyDerivation;

use Tourze\TLSCryptoHash\Tls\TLS12PRF;
use Tourze\TLSCryptoHash\Tls\TLS13HKDF;
use Tourze\TLSHandshakeNegotiation\Crypto\CipherSuite;

/**
 * 会话密钥派生器
 * 根据主密钥生成会话密钥
 */
class SessionKeysDeriver
{
    /**
     * TLS 1.2 PRF实例
     */
    private TLS12PRF $prf;

    /**
     * TLS 1.3 HKDF实例
     */
    private TLS13HKDF $hkdf;

    /**
     * 构造函数
     */
    public function __construct()
    {
        $this->prf = new TLS12PRF();
        $this->hkdf = new TLS13HKDF();
    }

    /**
     * 派生TLS 1.2密钥
     *
     * @param string $masterSecret 主密钥
     * @param string $clientRandom 客户端随机数
     * @param string $serverRandom 服务器随机数
     * @param int    $cipherSuite  密码套件
     *
     * @return SessionKeys 会话密钥
     */
    public function deriveTLS12Keys(string $masterSecret, string $clientRandom, string $serverRandom, int $cipherSuite): SessionKeys
    {
        // 根据密码套件确定密钥长度
        $keyLength = $this->getKeyLength($cipherSuite);
        $ivLength = $this->getIVLength($cipherSuite);
        $macKeyLength = $this->getMACKeyLength($cipherSuite);

        // 计算所需的密钥块总长度
        $keyBlockLength = 2 * ($keyLength + $ivLength + ($macKeyLength > 0 ? $macKeyLength : 0));

        // 生成密钥块
        $keyBlock = $this->prf->generateKeyBlock($masterSecret, $clientRandom, $serverRandom, $keyBlockLength);

        // 分割密钥块到各个密钥
        $pos = 0;
        $clientMACKey = null;
        $serverMACKey = null;

        if ($macKeyLength > 0) {
            $clientMACKey = substr($keyBlock, $pos, $macKeyLength);
            $pos += $macKeyLength;
            $serverMACKey = substr($keyBlock, $pos, $macKeyLength);
            $pos += $macKeyLength;
        }

        $clientWriteKey = substr($keyBlock, $pos, $keyLength);
        $pos += $keyLength;
        $serverWriteKey = substr($keyBlock, $pos, $keyLength);
        $pos += $keyLength;

        $clientWriteIV = substr($keyBlock, $pos, $ivLength);
        $pos += $ivLength;
        $serverWriteIV = substr($keyBlock, $pos, $ivLength);

        return new SessionKeys(
            $clientWriteKey,
            $serverWriteKey,
            $clientWriteIV,
            $serverWriteIV,
            $clientMACKey,
            $serverMACKey
        );
    }

    /**
     * 派生TLS 1.3握手密钥
     *
     * @param string $handshakeTraffic 握手流量密钥(客户端或服务器)
     * @param int    $cipherSuite      密码套件
     *
     * @return SessionKeys 会话密钥
     */
    public function deriveTLS13HandshakeKeys(string $handshakeTraffic, int $cipherSuite): SessionKeys
    {
        // 根据密码套件确定密钥长度
        $keyLength = $this->getKeyLength($cipherSuite);
        $ivLength = 12; // TLS 1.3 IV 长度固定为12字节

        // 客户端握手密钥和IV
        $clientWriteKey = $this->hkdf->expandLabel($handshakeTraffic, 'key', '', $keyLength);
        $clientWriteIV = $this->hkdf->expandLabel($handshakeTraffic, 'iv', '', $ivLength);

        // 服务器握手密钥和IV
        $serverWriteKey = $this->hkdf->expandLabel($handshakeTraffic, 'key', '', $keyLength);
        $serverWriteIV = $this->hkdf->expandLabel($handshakeTraffic, 'iv', '', $ivLength);

        return new SessionKeys(
            $clientWriteKey,
            $serverWriteKey,
            $clientWriteIV,
            $serverWriteIV
        );
    }

    /**
     * 派生TLS 1.3应用数据密钥
     *
     * @param string $applicationTraffic 应用流量密钥(客户端或服务器)
     * @param int    $cipherSuite        密码套件
     *
     * @return SessionKeys 会话密钥
     */
    public function deriveTLS13ApplicationKeys(string $applicationTraffic, int $cipherSuite): SessionKeys
    {
        // 应用数据密钥结构与握手密钥相同
        return $this->deriveTLS13HandshakeKeys($applicationTraffic, $cipherSuite);
    }

    /**
     * 获取密码套件的密钥长度
     *
     * @param int $cipherSuite 密码套件
     *
     * @return int 密钥长度(字节)
     */
    private function getKeyLength(int $cipherSuite): int
    {
        // 根据密码套件返回相应的密钥长度
        return match ($cipherSuite) {
            // AES-128密码套件
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_128_GCM_SHA256 => 16, // 128位 = 16字节

            // AES-256密码套件
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_AES_256_GCM_SHA384 => 32, // 256位 = 32字节

            // CHACHA20-POLY1305
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => 32, // 256位 = 32字节

            default => 16, // 默认16字节
        };
    }

    /**
     * 获取密码套件的IV长度
     *
     * @param int $cipherSuite 密码套件
     *
     * @return int IV长度(字节)
     */
    private function getIVLength(int $cipherSuite): int
    {
        // 根据密码套件和模式返回相应的IV长度
        return match ($cipherSuite) {
            // CBC模式
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA => 16, // 128位 = 16字节

            // GCM模式 (TLS 1.2)
            CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => 4, // 32位 = 4字节(显式随机数)

            // CHACHA20-POLY1305 (TLS 1.2)
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => 12, // 96位 = 12字节

            // TLS 1.3所有AEAD密码套件
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => 12, // 96位 = 12字节

            default => 12, // 默认12字节
        };
    }

    /**
     * 获取密码套件的MAC密钥长度
     *
     * @param int $cipherSuite 密码套件
     *
     * @return int MAC密钥长度(字节)，0表示不需要MAC密钥
     */
    private function getMACKeyLength(int $cipherSuite): int
    {
        // 根据密码套件返回相应的MAC密钥长度
        return match ($cipherSuite) {
            // SHA1 HMAC (20字节)
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA => 20,

            // AEAD模式(GCM, CHACHA20-POLY1305等)无需单独的MAC密钥
            default => 0,
        };
    }
}
