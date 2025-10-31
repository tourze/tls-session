<?php

declare(strict_types=1);

namespace Tourze\TLSSession\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSSession\ConcreteTLSSession;
use Tourze\TLSSession\SessionInterface;
use Tourze\TLSSession\TLSSession;

/**
 * 具体TLS会话测试
 *
 * @internal
 */
#[CoversClass(ConcreteTLSSession::class)]
final class ConcreteTLSSessionTest extends TestCase
{
    /**
     * 测试类继承关系
     */
    public function testInheritance(): void
    {
        $session = new ConcreteTLSSession();

        $this->assertInstanceOf(TLSSession::class, $session);
        $this->assertInstanceOf(SessionInterface::class, $session);
    }

    /**
     * 测试基本实例化
     */
    public function testInstantiation(): void
    {
        $session = new ConcreteTLSSession();
        $this->assertInstanceOf(ConcreteTLSSession::class, $session);
    }

    /**
     * 测试带参数的实例化
     */
    public function testInstantiationWithParameters(): void
    {
        $sessionId = 'test-session-id';
        $masterSecret = random_bytes(32);
        $cipherSuite = 'TLS_AES_128_GCM_SHA256';
        $tlsVersion = 0x0303;
        $timestamp = time();

        $session = new ConcreteTLSSession(
            sessionId: $sessionId,
            masterSecret: $masterSecret,
            cipherSuite: $cipherSuite,
            tlsVersion: $tlsVersion,
            timestamp: $timestamp
        );

        $this->assertEquals($sessionId, $session->getSessionId());
        $this->assertEquals($masterSecret, $session->getMasterSecret());
        $this->assertEquals($cipherSuite, $session->getCipherSuite());
        $this->assertEquals($timestamp, $session->getCreationTime());
    }

    /**
     * 测试继承的功能
     */
    public function testInheritedFunctionality(): void
    {
        $session = new ConcreteTLSSession();

        // 测试设置会话ID
        $sessionId = 'test-id';
        $session->setSessionId($sessionId);
        $this->assertEquals($sessionId, $session->getSessionId());

        // 测试设置密码套件
        $cipherSuite = 'TLS_AES_256_GCM_SHA384';
        $session->setCipherSuite($cipherSuite);
        $this->assertEquals($cipherSuite, $session->getCipherSuite());

        // 测试设置主密钥
        $masterSecret = random_bytes(48);
        $session->setMasterSecret($masterSecret);
        $this->assertEquals($masterSecret, $session->getMasterSecret());
    }

    /**
     * 测试会话有效性继承
     */
    public function testSessionValidityInheritance(): void
    {
        $session = new ConcreteTLSSession();

        // 新会话应该是有效的
        $this->assertTrue($session->isValid());

        // 设置有效期并测试
        $session->setLifetime(3600);
        $this->assertEquals(3600, $session->getLifetime());
        $this->assertTrue($session->isValid());
    }
}
