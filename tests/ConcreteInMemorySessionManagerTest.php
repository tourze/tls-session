<?php

declare(strict_types=1);

namespace Tourze\TLSSession\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSSession\ConcreteInMemorySessionManager;
use Tourze\TLSSession\InMemorySessionManager;
use Tourze\TLSSession\SessionManagerInterface;

/**
 * 具体内存会话管理器测试
 *
 * @internal
 */
#[CoversClass(ConcreteInMemorySessionManager::class)]
final class ConcreteInMemorySessionManagerTest extends TestCase
{
    private ConcreteInMemorySessionManager $manager;

    protected function setUp(): void
    {
        parent::setUp();

        $this->manager = new ConcreteInMemorySessionManager();
    }

    /**
     * 测试类继承关系
     */
    public function testInheritance(): void
    {
        $this->assertInstanceOf(InMemorySessionManager::class, $this->manager);
        $this->assertInstanceOf(SessionManagerInterface::class, $this->manager);
    }

    /**
     * 测试基本实例化
     */
    public function testInstantiation(): void
    {
        $manager = new ConcreteInMemorySessionManager();
        $this->assertInstanceOf(ConcreteInMemorySessionManager::class, $manager);
    }

    /**
     * 测试继承的会话创建功能
     */
    public function testCreateSessionInheritance(): void
    {
        $cipherSuite = 'TLS_AES_128_GCM_SHA256';
        $masterSecret = random_bytes(32);

        $session = $this->manager->createSession($cipherSuite, $masterSecret);

        $this->assertNotNull($session);
        $this->assertEquals($cipherSuite, $session->getCipherSuite());
        $this->assertEquals($masterSecret, $session->getMasterSecret());
    }
}
