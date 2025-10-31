<?php

declare(strict_types=1);

namespace Tourze\TLSSession\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSSession\ConcreteInMemorySessionManager;
use Tourze\TLSSession\ConcreteTLSSession;
use Tourze\TLSSession\InMemorySessionManager;
use Tourze\TLSSession\SessionInterface;
use Tourze\TLSSession\TLSSession;

/**
 * @internal
 */
#[CoversClass(InMemorySessionManager::class)]
final class InMemorySessionManagerTest extends TestCase
{
    private InMemorySessionManager $manager;

    protected function setUp(): void
    {
        parent::setUp();

        $this->manager = new ConcreteInMemorySessionManager();
    }

    public function testCreateSession(): void
    {
        $cipherSuite = 'TLS_AES_128_GCM_SHA256';
        $masterSecret = random_bytes(32);

        $session = $this->manager->createSession($cipherSuite, $masterSecret);

        $this->assertInstanceOf(SessionInterface::class, $session);
        $this->assertEquals($cipherSuite, $session->getCipherSuite());
        $this->assertEquals($masterSecret, $session->getMasterSecret());
        $this->assertNotEmpty($session->getSessionId());
    }

    public function testGetSessionById(): void
    {
        $cipherSuite = 'TLS_AES_128_GCM_SHA256';
        $masterSecret = random_bytes(32);

        $session = $this->manager->createSession($cipherSuite, $masterSecret);
        $sessionId = $session->getSessionId();

        $retrievedSession = $this->manager->getSessionById($sessionId);

        $this->assertInstanceOf(SessionInterface::class, $retrievedSession);
        $this->assertEquals($sessionId, $retrievedSession->getSessionId());
        $this->assertEquals($cipherSuite, $retrievedSession->getCipherSuite());
        $this->assertEquals($masterSecret, $retrievedSession->getMasterSecret());
    }

    public function testGetSessionByNonExistentId(): void
    {
        $retrievedSession = $this->manager->getSessionById('non-existent-id');

        $this->assertNull($retrievedSession);
    }

    public function testRemoveSession(): void
    {
        $session = $this->manager->createSession('TLS_AES_128_GCM_SHA256', random_bytes(32));
        $sessionId = $session->getSessionId();

        $result = $this->manager->removeSession($sessionId);

        $this->assertTrue($result);
        $this->assertNull($this->manager->getSessionById($sessionId));
    }

    public function testRemoveNonExistentSession(): void
    {
        $result = $this->manager->removeSession('non-existent-id');

        $this->assertFalse($result);
    }

    public function testStoreSession(): void
    {
        $session = new ConcreteTLSSession(
            sessionId: 'test-session-id',
            masterSecret: random_bytes(32),
            cipherSuite: 'TLS_AES_128_GCM_SHA256',
            tlsVersion: 0x0303,
            timestamp: time()
        );

        $result = $this->manager->storeSession($session);

        $this->assertTrue($result);
        $retrievedSession = $this->manager->getSessionById('test-session-id');
        $this->assertInstanceOf(SessionInterface::class, $retrievedSession);
        $this->assertEquals('test-session-id', $retrievedSession->getSessionId());
    }

    public function testCleanExpiredSessions(): void
    {
        // 创建会话
        $session1 = new ConcreteTLSSession('session-1', random_bytes(32), 'TLS_AES_128_GCM_SHA256', 0x0303, time());
        $session2 = new ConcreteTLSSession('session-2', random_bytes(32), 'TLS_AES_128_GCM_SHA256', 0x0303, time() - 7200); // 过期

        // 手动设置会话有效期为1小时
        $session1->setLifetime(3600);
        $session2->setLifetime(3600);

        // 存储会话
        $this->manager->storeSession($session1);
        $this->manager->storeSession($session2);

        // 清理过期会话
        $count = $this->manager->cleanExpiredSessions();

        $this->assertEquals(1, $count);
        $this->assertNotNull($this->manager->getSessionById('session-1'));
        $this->assertNull($this->manager->getSessionById('session-2'));
    }
}
