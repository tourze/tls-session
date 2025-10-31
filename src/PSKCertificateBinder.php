<?php

declare(strict_types=1);

namespace Tourze\TLSSession;

use Tourze\TLSX509Core\Certificate\CertificateInterface;

/**
 * PSK证书绑定器
 *
 * 负责管理PSK与证书之间的绑定关系
 */
class PSKCertificateBinder
{
    /**
     * PSK到证书的映射
     *
     * @var array<string, CertificateInterface> PSK身份映射到证书
     */
    private array $pskToCertificateMap = [];

    /**
     * 证书到PSK身份列表的映射
     *
     * @var array<string, array<string>> 证书哈希映射到PSK身份列表
     */
    private array $certificateToPSKMap = [];

    /**
     * 绑定证书到PSK
     *
     * @param string               $pskIdentity PSK标识
     * @param CertificateInterface $certificate 证书对象
     */
    public function bindCertificateToPSK(string $pskIdentity, CertificateInterface $certificate): self
    {
        $this->pskToCertificateMap[$pskIdentity] = $certificate;

        // 使用证书哈希作为键，便于查找
        $certHash = $this->getCertificateHash($certificate);
        if (!isset($this->certificateToPSKMap[$certHash])) {
            $this->certificateToPSKMap[$certHash] = [];
        }

        $this->certificateToPSKMap[$certHash][] = $pskIdentity;

        return $this;
    }

    /**
     * 获取PSK绑定的证书
     *
     * @param string $pskIdentity PSK标识
     *
     * @return CertificateInterface|null 证书对象，未绑定则返回null
     */
    public function getCertificateForPSK(string $pskIdentity): ?CertificateInterface
    {
        return $this->pskToCertificateMap[$pskIdentity] ?? null;
    }

    /**
     * 移除PSK的绑定
     *
     * @param string $pskIdentity PSK标识
     *
     * @return bool 是否成功移除
     */
    public function removeBindingForPSK(string $pskIdentity): bool
    {
        if (!isset($this->pskToCertificateMap[$pskIdentity])) {
            return false;
        }

        $certificate = $this->pskToCertificateMap[$pskIdentity];
        $certHash = $this->getCertificateHash($certificate);

        // 从证书到PSK映射中移除
        if (isset($this->certificateToPSKMap[$certHash])) {
            $this->certificateToPSKMap[$certHash] = array_filter(
                $this->certificateToPSKMap[$certHash],
                fn ($id) => $id !== $pskIdentity
            );

            // 如果证书没有绑定的PSK，移除该条目
            if ([] === $this->certificateToPSKMap[$certHash]) {
                unset($this->certificateToPSKMap[$certHash]);
            }
        }

        // 移除PSK到证书的映射
        unset($this->pskToCertificateMap[$pskIdentity]);

        return true;
    }

    /**
     * 检查PSK是否已绑定到证书
     *
     * @param string $pskIdentity PSK标识
     *
     * @return bool 是否已绑定
     */
    public function isPSKBoundToCertificate(string $pskIdentity): bool
    {
        return isset($this->pskToCertificateMap[$pskIdentity]);
    }

    /**
     * 获取绑定到指定证书的所有PSK身份
     *
     * @param CertificateInterface $certificate 证书对象
     *
     * @return array<string> PSK身份列表
     */
    public function getPSKIdentitiesForCertificate(CertificateInterface $certificate): array
    {
        $certHash = $this->getCertificateHash($certificate);

        return $this->certificateToPSKMap[$certHash] ?? [];
    }

    /**
     * 获取证书的哈希值
     *
     * 注意：此函数用于内部映射，不是加密安全的哈希
     *
     * @param CertificateInterface $certificate 证书对象
     *
     * @return string 证书哈希
     */
    private function getCertificateHash(CertificateInterface $certificate): string
    {
        // 通过spl_object_hash获取对象唯一标识
        // 在实际项目中，可以考虑使用证书的指纹或其他唯一标识
        return spl_object_hash($certificate);
    }
}
