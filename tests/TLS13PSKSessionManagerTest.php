<?php

declare(strict_types=1);

namespace Tourze\TLSSession\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSSession\TLS13PSKSession;
use Tourze\TLSSession\TLS13PSKSessionManager;

/**
 * TLS 1.3 PSK会话管理器测试
 *
 * @internal
 */
#[CoversClass(TLS13PSKSessionManager::class)]
final class TLS13PSKSessionManagerTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // TLS13PSKSessionManager 是一个会话管理服务，直接实例化
    }

    /**
     * 测试创建PSK会话方法
     */
    public function testCreatePSKSession(): void
    {
        $manager = new TLS13PSKSessionManager();

        $cipherSuite = 0x1301; // TLS_AES_128_GCM_SHA256
        $masterSecret = random_bytes(32);
        $resumptionMasterSecret = random_bytes(32);
        $ticketNonce = random_bytes(16);

        $session = $manager->createPSKSession(
            $cipherSuite,
            $masterSecret,
            $resumptionMasterSecret,
            $ticketNonce
        );

        $this->assertInstanceOf(TLS13PSKSession::class, $session);
        $this->assertNotEmpty($session->getSessionId());
        $this->assertNotEmpty($session->getPskIdentity());
        $this->assertEquals($masterSecret, $session->getMasterSecret());
        $this->assertEquals($resumptionMasterSecret, $session->getResumptionMasterSecret());
        $this->assertEquals($ticketNonce, $session->getTicketNonce());
        $this->assertTrue($session->isValid());
    }

    /**
     * 测试PSK会话创建和获取
     */
    public function testPSKSessionCreateAndGet(): void
    {
        $manager = new TLS13PSKSessionManager();

        // 创建PSK会话
        $cipherSuite = 0x1301; // TLS_AES_128_GCM_SHA256
        $masterSecret = random_bytes(32);
        $resumptionMasterSecret = random_bytes(32);
        $ticketNonce = random_bytes(16);

        $session = $manager->createPSKSession(
            $cipherSuite,
            $masterSecret,
            $resumptionMasterSecret,
            $ticketNonce
        );

        // 验证会话基本属性
        $this->assertInstanceOf(TLS13PSKSession::class, $session);
        $this->assertNotEmpty($session->getPskIdentity());
        $this->assertTrue($session->isValid());

        // 通过PSK身份获取会话
        $pskIdentity = $session->getPskIdentity();
        $retrievedSession = $manager->getSessionByPskIdentity($pskIdentity);

        $this->assertSame($session, $retrievedSession);
        $this->assertEquals($session->getSessionId(), $retrievedSession->getSessionId());
        $this->assertEquals($session->getCipherSuite(), $retrievedSession->getCipherSuite());

        // 测试获取不存在的会话
        $this->assertNull($manager->getSessionByPskIdentity('non_existent_id'));
    }

    /**
     * 测试移除PSK会话
     */
    public function testRemovePSKSession(): void
    {
        $manager = new TLS13PSKSessionManager();

        // 创建会话
        $session = $manager->createPSKSession(
            0x1301, // TLS_AES_128_GCM_SHA256
            random_bytes(32),
            random_bytes(32),
            random_bytes(16)
        );

        $pskIdentity = $session->getPskIdentity();

        // 验证会话存在
        $this->assertNotNull($manager->getSessionByPskIdentity($pskIdentity));

        // 移除存在的会话
        $this->assertTrue($manager->removePSKSession($pskIdentity));

        // 验证会话已被移除
        $this->assertNull($manager->getSessionByPskIdentity($pskIdentity));

        // 尝试移除不存在的会话
        $this->assertFalse($manager->removePSKSession('non_existent_id'));

        // 再次尝试移除已移除的会话
        $this->assertFalse($manager->removePSKSession($pskIdentity));
    }

    /**
     * 测试清理过期PSK会话
     */
    public function testCleanExpiredPSKSessions(): void
    {
        $manager = new TLS13PSKSessionManager();

        // 创建一个正常会话
        $validSession = $manager->createPSKSession(
            0x1301,
            random_bytes(32),
            random_bytes(32),
            random_bytes(16)
        );

        // 创建一个过期的会话 - 通过反射修改其创建时间
        $expiredSession = $manager->createPSKSession(
            0x1301,
            random_bytes(32),
            random_bytes(32),
            random_bytes(16)
        );

        // 使用反射设置过期时间（设置为很久以前）
        // 需要通过父类 TLSSession 来访问 creationTime 属性
        $tlsSessionReflection = new \ReflectionClass(get_parent_class($expiredSession));
        $creationTimeProperty = $tlsSessionReflection->getProperty('creationTime');
        $creationTimeProperty->setValue($expiredSession, time() - 7200); // 2小时前

        // 同时设置短的生命周期来测试过期逻辑
        $lifetimeProperty = $tlsSessionReflection->getProperty('lifetime');
        $lifetimeProperty->setValue($expiredSession, 3600); // 1小时生命周期

        // 验证会话状态
        $this->assertTrue($validSession->isValid());
        $this->assertFalse($expiredSession->isValid()); // 应该过期

        // 执行清理
        $cleanedCount = $manager->cleanExpiredPSKSessions();

        // 验证至少清理了过期会话
        $this->assertGreaterThanOrEqual(1, $cleanedCount);

        // 验证有效会话依然存在
        $this->assertNotNull($manager->getSessionByPskIdentity($validSession->getPskIdentity()));

        // 验证过期会话被清理
        $this->assertNull($manager->getSessionByPskIdentity($expiredSession->getPskIdentity()));
    }

    /**
     * 测试早期数据设置
     */
    public function testEarlyDataSettings(): void
    {
        $manager = new TLS13PSKSessionManager();

        // 使用反射检查默认值
        $reflectionClass = new \ReflectionClass($manager);
        $allowEarlyDataProperty = $reflectionClass->getProperty('allowEarlyData');
        $maxEarlyDataSizeProperty = $reflectionClass->getProperty('maxEarlyDataSize');

        // 验证默认值
        $this->assertFalse($allowEarlyDataProperty->getValue($manager));
        $this->assertEquals(0, $maxEarlyDataSizeProperty->getValue($manager));

        // 设置早期数据支持
        $manager->setEarlyDataAllowed(true);
        $this->assertTrue($allowEarlyDataProperty->getValue($manager));

        // 设置最大早期数据大小
        $maxSize = 16384;
        $manager->setMaxEarlyDataSize($maxSize);
        $this->assertEquals($maxSize, $maxEarlyDataSizeProperty->getValue($manager));
        $this->assertTrue($allowEarlyDataProperty->getValue($manager)); // 应该自动启用

        // 创建会话验证早期数据设置
        $session = $manager->createPSKSession(
            0x1301,
            random_bytes(32),
            random_bytes(32),
            random_bytes(16)
        );

        // 验证会话具有早期数据支持
        $this->assertTrue($session->isEarlyDataAllowed());
        $this->assertEquals($maxSize, $session->getMaxEarlyDataSize());

        // 设置为0应该禁用早期数据
        $manager->setMaxEarlyDataSize(0);
        $this->assertEquals(0, $maxEarlyDataSizeProperty->getValue($manager));
        $this->assertFalse($allowEarlyDataProperty->getValue($manager));

        // 创建新会话验证早期数据被禁用
        $newSession = $manager->createPSKSession(
            0x1301,
            random_bytes(32),
            random_bytes(32),
            random_bytes(16)
        );

        $this->assertFalse($newSession->isEarlyDataAllowed());
        $this->assertEquals(0, $newSession->getMaxEarlyDataSize());
    }

    /**
     * 测试清理所有会话
     */
    public function testCleanAllSessions(): void
    {
        $manager = new TLS13PSKSessionManager();

        // 创建一些PSK会话
        $session1 = $manager->createPSKSession(
            0x1301,
            random_bytes(32),
            random_bytes(32),
            random_bytes(16)
        );

        $session2 = $manager->createPSKSession(
            0x1302, // TLS_AES_256_GCM_SHA384
            random_bytes(32),
            random_bytes(32),
            random_bytes(16)
        );

        // 验证会话存在
        $this->assertNotNull($manager->getSessionByPskIdentity($session1->getPskIdentity()));
        $this->assertNotNull($manager->getSessionByPskIdentity($session2->getPskIdentity()));

        // 使用反射检查PSK会话数量
        $reflectionClass = new \ReflectionClass($manager);
        $pskSessionsProperty = $reflectionClass->getProperty('pskSessions');
        $this->assertCount(2, $pskSessionsProperty->getValue($manager));

        // 执行清理所有会话
        $manager->cleanAllSessions();

        // 验证所有PSK会话已清空
        $this->assertEmpty($pskSessionsProperty->getValue($manager));

        // 验证无法再获取之前的会话
        $this->assertNull($manager->getSessionByPskIdentity($session1->getPskIdentity()));
        $this->assertNull($manager->getSessionByPskIdentity($session2->getPskIdentity()));
    }
}
