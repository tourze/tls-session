<?php

declare(strict_types=1);

namespace Tourze\TLSSession\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSSession\PSKCertificateBinder;
use Tourze\TLSX509Core\Certificate\CertificateInterface;

/**
 * @internal
 */
#[CoversClass(PSKCertificateBinder::class)]
final class PSKCertificateBinderTest extends TestCase
{
    private PSKCertificateBinder $binder;

    protected function setUp(): void
    {
        parent::setUp();

        $this->binder = new PSKCertificateBinder();
    }

    private function createTestCertificate(): CertificateInterface
    {
        return new TestCertificate();
    }

    public function testBindCertificateToPSK(): void
    {
        $pskIdentity = 'test-psk-identity';
        $certificate = $this->createTestCertificate();

        $result = $this->binder->bindCertificateToPSK($pskIdentity, $certificate);

        // 验证方法返回自身用于链式调用
        $this->assertSame($this->binder, $result);

        // 验证绑定是否成功
        $this->assertTrue($this->binder->isPSKBoundToCertificate($pskIdentity));
    }

    public function testGetCertificateForPSK(): void
    {
        $pskIdentity = 'test-psk-identity';
        $certificate = $this->createTestCertificate();

        // 绑定证书到PSK
        $this->binder->bindCertificateToPSK($pskIdentity, $certificate);

        // 获取PSK对应的证书
        $retrievedCertificate = $this->binder->getCertificateForPSK($pskIdentity);

        // 验证是否返回正确的证书
        $this->assertSame($certificate, $retrievedCertificate);
    }

    public function testGetCertificateForNonExistentPSK(): void
    {
        // 尝试获取不存在的PSK对应的证书
        $retrievedCertificate = $this->binder->getCertificateForPSK('non-existent-psk');

        // 验证是否返回null
        $this->assertNull($retrievedCertificate);
    }

    public function testRemoveBindingForPSK(): void
    {
        $pskIdentity = 'test-psk-identity';
        $certificate = $this->createTestCertificate();

        // 绑定证书到PSK
        $this->binder->bindCertificateToPSK($pskIdentity, $certificate);

        // 验证绑定是否成功
        $this->assertTrue($this->binder->isPSKBoundToCertificate($pskIdentity));

        // 移除绑定
        $result = $this->binder->removeBindingForPSK($pskIdentity);

        // 验证是否成功移除
        $this->assertTrue($result);
        $this->assertFalse($this->binder->isPSKBoundToCertificate($pskIdentity));
        $this->assertNull($this->binder->getCertificateForPSK($pskIdentity));
    }

    public function testRemoveBindingForNonExistentPSK(): void
    {
        // 尝试移除不存在的PSK绑定
        $result = $this->binder->removeBindingForPSK('non-existent-psk');

        // 验证移除失败
        $this->assertFalse($result);
    }

    public function testGetPSKIdentitiesForCertificate(): void
    {
        $pskIdentity1 = 'test-psk-identity-1';
        $pskIdentity2 = 'test-psk-identity-2';
        $certificate = $this->createTestCertificate();

        // 绑定多个PSK到同一个证书
        $this->binder->bindCertificateToPSK($pskIdentity1, $certificate);
        $this->binder->bindCertificateToPSK($pskIdentity2, $certificate);

        // 获取证书对应的PSK身份列表
        $pskIdentities = $this->binder->getPSKIdentitiesForCertificate($certificate);

        // 验证是否包含所有绑定的PSK身份
        $this->assertContains($pskIdentity1, $pskIdentities);
        $this->assertContains($pskIdentity2, $pskIdentities);
        $this->assertCount(2, $pskIdentities);
    }
}
