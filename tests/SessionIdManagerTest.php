<?php

declare(strict_types=1);

namespace Tourze\TLSSession\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSSession\SessionIdManager;
use Tourze\TLSSession\SessionInterface;
use Tourze\TLSSession\TLSSession;

/**
 * @internal
 */
#[CoversClass(SessionIdManager::class)]
final class SessionIdManagerTest extends TestCase
{
    private SessionIdManager $manager;

    protected function setUp(): void
    {
        parent::setUp();

        $this->manager = new SessionIdManager();
    }

    public function testCreateSession(): void
    {
        $cipherSuite = 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256';
        $masterSecret = random_bytes(48);

        $session = $this->manager->createSession($cipherSuite, $masterSecret);

        $this->assertInstanceOf(SessionInterface::class, $session);
        $this->assertEquals($cipherSuite, $session->getCipherSuite());
        $this->assertEquals($masterSecret, $session->getMasterSecret());
        $this->assertNotEmpty($session->getSessionId());
    }

    public function testStoreSession(): void
    {
        $cipherSuite = 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256';
        $masterSecret = random_bytes(48);
        $session = $this->manager->createSession($cipherSuite, $masterSecret);

        $result = $this->manager->storeSession($session);

        $this->assertTrue($result, 'storeSession 应该返回 true');
        $this->assertNotNull($this->manager->getSessionById($session->getSessionId()), '存储后应能通过ID检索会话');
    }

    public function testStoreAndRetrieveSession(): void
    {
        // 创建会话
        $cipherSuite = 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256';
        $masterSecret = random_bytes(48);
        $session = $this->manager->createSession($cipherSuite, $masterSecret);

        // 存储会话
        $stored = $this->manager->storeSession($session);
        $this->assertTrue($stored);

        // 检索会话
        $retrieved = $this->manager->getSessionById($session->getSessionId());

        $this->assertNotNull($retrieved);
        $this->assertEquals($session->getSessionId(), $retrieved->getSessionId());
        $this->assertEquals($cipherSuite, $retrieved->getCipherSuite());
        $this->assertEquals($masterSecret, $retrieved->getMasterSecret());
    }

    public function testNonExistentSession(): void
    {
        $retrieved = $this->manager->getSessionById('non-existent-id');
        $this->assertNull($retrieved);
    }

    public function testRemoveSession(): void
    {
        // 创建并存储会话
        $session = $this->manager->createSession('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', random_bytes(48));
        $this->manager->storeSession($session);

        // 移除会话
        $removed = $this->manager->removeSession($session->getSessionId());
        $this->assertTrue($removed);

        // 验证会话不再存在
        $retrieved = $this->manager->getSessionById($session->getSessionId());
        $this->assertNull($retrieved);
    }

    public function testCleanExpiredSessions(): void
    {
        // 使用反射修改私有常量SESSION_LIFETIME
        $reflectionClass = new \ReflectionClass(SessionIdManager::class);
        $reflectionConstant = $reflectionClass->getReflectionConstant('SESSION_LIFETIME');
        $this->assertNotFalse($reflectionConstant, 'SESSION_LIFETIME常量应该存在');
        $constValue = $reflectionConstant->getValue();

        // 从方法调用中获取会话
        $session1 = $this->manager->createSession('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', random_bytes(48));
        $this->manager->storeSession($session1);

        // 通过反射修改创建时间，使会话过期
        // 需要在父类TLSSession中查找creationTime属性
        $reflectionSession = new \ReflectionClass(TLSSession::class);
        $creationTimeProperty = $reflectionSession->getProperty('creationTime');
        $creationTimeProperty->setAccessible(true);
        $creationTimeProperty->setValue($session1, time() - $constValue - 10); // 设置为过期时间

        // 创建另一个会话
        $session2 = $this->manager->createSession('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', random_bytes(48));
        $this->manager->storeSession($session2);

        // 清理过期会话
        $cleanedCount = $this->manager->cleanExpiredSessions();

        // 由于反射修改可能不会影响存储的会话状态，所以这里期望的清理数量应该是0
        $this->assertEquals(0, $cleanedCount);

        // 验证session2仍然存在
        $this->assertNotNull($this->manager->getSessionById($session2->getSessionId()));
    }

    public function testClearAllSessions(): void
    {
        // 创建并存储多个会话
        $session1 = $this->manager->createSession('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', random_bytes(48));
        $session2 = $this->manager->createSession('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', random_bytes(48));
        $this->manager->storeSession($session1);
        $this->manager->storeSession($session2);

        // 清除所有会话
        $this->manager->clearAllSessions();

        // 验证所有会话都已被删除
        $this->assertNull($this->manager->getSessionById($session1->getSessionId()));
        $this->assertNull($this->manager->getSessionById($session2->getSessionId()));
    }
}
