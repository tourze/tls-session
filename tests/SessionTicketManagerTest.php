<?php

declare(strict_types=1);

namespace Tourze\TLSSession\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSSession\ConcreteTLSSession;
use Tourze\TLSSession\SessionInterface;
use Tourze\TLSSession\SessionTicket;
use Tourze\TLSSession\SessionTicketManager;
use Tourze\TLSSession\TLSSession;

/**
 * 会话票据管理器测试
 *
 * @internal
 */
#[CoversClass(SessionTicketManager::class)]
final class SessionTicketManagerTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // SessionTicketManager 是一个票据管理服务，直接实例化
    }

    /**
     * 测试生成新密钥
     */
    public function testGenerateNewKey(): void
    {
        $manager = new SessionTicketManager();

        // 验证初始密钥已创建
        $activeKey = $manager->getActiveKey();
        $this->assertNotNull($activeKey);
        $this->assertArrayHasKey('name', $activeKey);
        $this->assertArrayHasKey('key', $activeKey);
        $this->assertArrayHasKey('encryption_key', $activeKey['key']);
        $this->assertArrayHasKey('hmac_key', $activeKey['key']);

        // 生成新密钥
        $newKeyName = $manager->generateNewKey();

        // 验证新密钥被激活
        $newActiveKey = $manager->getActiveKey();
        $this->assertNotNull($newActiveKey, '活动密钥不应为null');
        $this->assertEquals($newKeyName, $newActiveKey['name']);
    }

    /**
     * 测试轮换密钥
     */
    public function testRotateKeys(): void
    {
        $manager = new SessionTicketManager();

        // 记录初始密钥数量
        $ticketKeysReflection = new \ReflectionProperty($manager, 'ticketKeys');
        $initialKeysCount = count($ticketKeysReflection->getValue($manager));

        // 添加多个密钥
        for ($i = 0; $i < 5; ++$i) {
            $manager->generateNewKey();
        }

        // 验证已添加5个新密钥 + 1个初始密钥 = 6个密钥
        $this->assertCount(6, $ticketKeysReflection->getValue($manager));

        // 轮换密钥，保留最新的3个
        $activeKeyName = $manager->rotateKeys(3);

        // 验证返回的活动密钥名称不为空
        $this->assertNotEmpty($activeKeyName);

        // 验证密钥数量不超过3
        $this->assertCount(3, $ticketKeysReflection->getValue($manager));

        // 验证当前活动密钥确实可用
        $activeKey = $manager->getActiveKey();
        $this->assertNotNull($activeKey, '活动密钥不应为空');
        $this->assertEquals($activeKeyName, $activeKey['name'], '返回的活动密钥名称应与实际活动密钥匹配');

        // 验证活动密钥确实存在于密钥列表中
        $keyByName = $manager->getKeyByName($activeKeyName);
        $this->assertNotNull($keyByName, '应该能通过名称获取活动密钥');
    }

    /**
     * 测试创建票据方法
     */
    public function testCreateTicket(): void
    {
        $manager = new SessionTicketManager();

        $session = new ConcreteTLSSession(
            sessionId: bin2hex(random_bytes(16)),
            masterSecret: random_bytes(48),
            cipherSuite: 'TLS_AES_128_GCM_SHA256',
            tlsVersion: 0x0303,
            timestamp: time()
        );

        $ticket = $manager->createTicket($session);

        $this->assertInstanceOf(SessionTicket::class, $ticket);
        $this->assertNotEmpty($ticket->getKeyName());
        $this->assertNotEmpty($ticket->getIV());
        $this->assertNotEmpty($ticket->getEncryptedState());
        $this->assertNotEmpty($ticket->getHMAC());
    }

    /**
     * 测试解密票据方法
     */
    public function testDecryptTicket(): void
    {
        $manager = new SessionTicketManager();

        $session = new ConcreteTLSSession(
            sessionId: bin2hex(random_bytes(16)),
            masterSecret: random_bytes(48),
            cipherSuite: 'TLS_AES_128_GCM_SHA256',
            tlsVersion: 0x0303,
            timestamp: time()
        );

        $ticket = $manager->createTicket($session);
        $decryptedSession = $manager->decryptTicket($ticket);

        $this->assertNotNull($decryptedSession);
        $this->assertInstanceOf(SessionInterface::class, $decryptedSession);
        $this->assertEquals($session->getSessionId(), $decryptedSession->getSessionId());
        $this->assertEquals($session->getCipherSuite(), $decryptedSession->getCipherSuite());
    }

    /**
     * 测试创建和解密票据
     */
    public function testCreateAndDecryptTicket(): void
    {
        $manager = new SessionTicketManager();

        // 创建会话
        $sessionId = bin2hex(random_bytes(16));
        $cipherSuite = 'TLS_AES_128_GCM_SHA256';
        $masterSecret = random_bytes(48);
        $timestamp = time();

        $session = new ConcreteTLSSession(
            $sessionId,
            $masterSecret,
            $cipherSuite,
            0x0303, // TLS 1.2
            $timestamp
        );

        // 创建票据
        $ticket = $manager->createTicket($session);

        // 验证票据基本属性
        $this->assertInstanceOf(SessionTicket::class, $ticket);
        $this->assertNotEmpty($ticket->getKeyName());
        $this->assertNotEmpty($ticket->getIV());
        $this->assertNotEmpty($ticket->getEncryptedState());
        $this->assertNotEmpty($ticket->getHMAC());

        // 验证使用正确密钥可以解密状态
        $keyInfo = $manager->getKeyByName($ticket->getKeyName());
        $this->assertNotNull($keyInfo, '无法获取密钥信息');

        $decryptedMessage = openssl_decrypt(
            $ticket->getEncryptedState(),
            'aes-256-cbc',
            $keyInfo['encryption_key'],
            OPENSSL_RAW_DATA,
            $ticket->getIV()
        );

        $this->assertNotFalse($decryptedMessage, '解密失败或密钥不匹配');

        // 验证解密的消息是有效的JSON并包含正确的字段
        $decoded = json_decode($decryptedMessage, true);
        $this->assertIsArray($decoded, '解密的消息不是有效的JSON格式');
        $this->assertArrayHasKey('session_id', $decoded);
        $this->assertArrayHasKey('cipher_suite', $decoded);
        $this->assertArrayHasKey('master_secret', $decoded);
        $this->assertArrayHasKey('creation_time', $decoded);

        // 测试完整的解密票据方法
        $decryptedSession = $manager->decryptTicket($ticket);

        // 验证解密结果
        $this->assertNotNull($decryptedSession, 'decryptTicket返回了空值');
        $this->assertInstanceOf(SessionInterface::class, $decryptedSession);

        // 验证会话属性正确恢复
        $this->assertEquals($sessionId, $decryptedSession->getSessionId());
        $this->assertEquals($cipherSuite, $decryptedSession->getCipherSuite());
        $this->assertEquals($masterSecret, $decryptedSession->getMasterSecret());
        $this->assertEquals($timestamp, $decryptedSession->getCreationTime());
    }

    /**
     * 测试使用未知密钥解密票据
     */
    public function testDecryptWithUnknownKey(): void
    {
        $manager1 = new SessionTicketManager();
        $manager2 = new SessionTicketManager();

        // 使用管理器1创建会话和票据
        $session = new ConcreteTLSSession(
            sessionId: bin2hex(random_bytes(16)),
            cipherSuite: 'TLS_AES_128_GCM_SHA256',
            masterSecret: random_bytes(48),
            timestamp: time()
        );

        $ticket = $manager1->createTicket($session);

        // 使用管理器2尝试解密票据（应失败，因为密钥不同）
        $decryptedSession = $manager2->decryptTicket($ticket);
        $this->assertNull($decryptedSession);
    }

    /**
     * 测试篡改票据
     */
    public function testTamperedTicket(): void
    {
        $manager = new SessionTicketManager();

        // 创建会话和票据
        $session = new ConcreteTLSSession(
            sessionId: bin2hex(random_bytes(16)),
            cipherSuite: 'TLS_AES_128_GCM_SHA256',
            masterSecret: random_bytes(48),
            timestamp: time()
        );

        $ticket = $manager->createTicket($session);

        // 篡改票据数据
        $tamperedTicket = clone $ticket;
        $tamperedTicket->setEncryptedState($ticket->getEncryptedState() . 'tampered');

        // 验证篡改票据无法解密
        $decryptedSession = $manager->decryptTicket($tamperedTicket);
        $this->assertNull($decryptedSession);
    }

    /**
     * 测试票据生命周期设置
     */
    public function testTicketLifetime(): void
    {
        $manager = new SessionTicketManager();

        // 验证默认生命周期
        $this->assertEquals(3600 * 24, $manager->getTicketLifetime()); // 默认24小时

        // 设置新生命周期
        $manager->setTicketLifetime(3600); // 1小时
        $this->assertEquals(3600, $manager->getTicketLifetime());
    }
}
