<?php

declare(strict_types=1);

namespace Tourze\TLSSession\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSSession\ConcreteTLSSession;
use Tourze\TLSSession\TLSSession;

/**
 * TLS会话测试
 *
 * @internal
 */
#[CoversClass(TLSSession::class)]
final class TLSSessionTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // TLSSession 是一个简单的会话对象，直接实例化
    }

    /**
     * 测试会话基本功能
     */
    public function testBasicSessionFunctionality(): void
    {
        $sessionId = bin2hex(random_bytes(16));
        $cipherSuite = 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'; // 使用字符串而非整数
        $masterSecret = random_bytes(48);
        $creationTime = time();

        $session = new ConcreteTLSSession(
            sessionId: $sessionId,
            cipherSuite: $cipherSuite,
            masterSecret: $masterSecret,
            timestamp: $creationTime
        );

        $this->assertEquals($sessionId, $session->getSessionId());
        $this->assertEquals($cipherSuite, $session->getCipherSuite());
        $this->assertEquals($masterSecret, $session->getMasterSecret());
        $this->assertEquals($creationTime, $session->getCreationTime());

        // 测试会话有效期
        $this->assertEquals(3600, $session->getLifetime()); // 默认1小时
        $this->assertTrue($session->isValid());

        // 测试设置新值
        $newSessionId = bin2hex(random_bytes(16));
        $newCipherSuite = 'TLS_AES_128_GCM_SHA256'; // 使用字符串而非整数
        $newMasterSecret = random_bytes(48);
        $newCreationTime = time() - 1800; // 30分钟前

        $session->setSessionId($newSessionId);
        $session->setCipherSuite($newCipherSuite);
        $session->setMasterSecret($newMasterSecret);
        $session->setCreationTime($newCreationTime);

        $this->assertEquals($newSessionId, $session->getSessionId());
        $this->assertEquals($newCipherSuite, $session->getCipherSuite());
        $this->assertEquals($newMasterSecret, $session->getMasterSecret());
        $this->assertEquals($newCreationTime, $session->getCreationTime());
    }

    /**
     * 测试会话有效期
     */
    public function testSessionValidity(): void
    {
        $sessionId = bin2hex(random_bytes(16));
        $cipherSuite = 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'; // 使用字符串而非整数
        $masterSecret = random_bytes(48);

        // 创建会话并设置较短有效期
        $session = new ConcreteTLSSession(
            sessionId: $sessionId,
            cipherSuite: $cipherSuite,
            masterSecret: $masterSecret
        );
        $session->setLifetime(60); // 1分钟

        // 验证当前有效
        $this->assertTrue($session->isValid());

        // 验证30秒后仍有效
        $this->assertTrue($session->isValid($session->getCreationTime() + 30));

        // 验证61秒后已过期
        $this->assertFalse($session->isValid($session->getCreationTime() + 61));

        // 验证设置更长的有效期
        $session->setLifetime(3600 * 24); // 24小时
        $this->assertTrue($session->isValid($session->getCreationTime() + 3600)); // 1小时后
        $this->assertTrue($session->isValid($session->getCreationTime() + 3600 * 23)); // 23小时后
        $this->assertFalse($session->isValid($session->getCreationTime() + 3600 * 25)); // 25小时后
    }

    /**
     * 测试会话ID长度限制
     */
    public function testSessionIdLengthConstraint(): void
    {
        $session = new ConcreteTLSSession();

        // 测试设置32字节的会话ID（最大长度）
        $maxLengthId = str_repeat('a', 32);
        $session->setSessionId($maxLengthId);
        $this->assertEquals($maxLengthId, $session->getSessionId());

        // 测试设置超过32字节的会话ID（应抛出异常）
        $tooLongId = str_repeat('a', 33);
        $this->expectException(\InvalidArgumentException::class);
        $session->setSessionId($tooLongId);
    }

    /**
     * 测试构造函数默认值
     */
    public function testConstructorDefaults(): void
    {
        $session = new ConcreteTLSSession();

        $this->assertEquals('', $session->getSessionId());
        $this->assertEquals('', $session->getCipherSuite()); // 修正为空字符串
        $this->assertEquals('', $session->getMasterSecret());
        $this->assertGreaterThanOrEqual(time() - 1, $session->getCreationTime());
        $this->assertLessThanOrEqual(time(), $session->getCreationTime());
    }
}
