<?php

declare(strict_types=1);

namespace Tourze\TLSSession\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSSession\TLS13PSKSession;

/**
 * @internal
 */
#[CoversClass(TLS13PSKSession::class)]
final class TLS13PSKSessionTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // TLS13PSKSession 是一个简单的会话对象，直接实例化
    }

    /**
     * 测试创建基本PSK会话
     */
    public function testCreateBasicPSKSession(): void
    {
        $sessionId = bin2hex(random_bytes(16));
        $pskIdentity = bin2hex(random_bytes(16));
        $masterSecret = random_bytes(32);
        $resumptionMasterSecret = random_bytes(32);
        $ticketNonce = random_bytes(16);
        $ticketAgeAdd = mt_rand(0, 1000000);
        $timestamp = time();

        $session = new TLS13PSKSession(
            $sessionId,
            0, // 使用setCipherSuite方法设置
            $masterSecret,
            $timestamp,
            $pskIdentity,
            $ticketAgeAdd,
            $ticketNonce,
            $resumptionMasterSecret
        );

        // 设置加密套件
        $session->setCipherSuite('TLS_AES_128_GCM_SHA256');

        // 验证基本属性
        $this->assertEquals($sessionId, $session->getSessionId());
        $this->assertEquals('TLS_AES_128_GCM_SHA256', $session->getCipherSuite());
        $this->assertEquals($masterSecret, $session->getMasterSecret());
        $this->assertEquals($timestamp, $session->getCreationTime());
        $this->assertEquals($pskIdentity, $session->getPskIdentity());
        $this->assertEquals($ticketAgeAdd, $session->getTicketAgeAdd());
        $this->assertEquals($ticketNonce, $session->getTicketNonce());
        $this->assertEquals($resumptionMasterSecret, $session->getResumptionMasterSecret());

        // 验证TLS版本（应为TLS 1.3）
        $this->assertEquals(0x0304, $session->getTlsVersion());

        // 验证早期数据默认设置
        $this->assertFalse($session->isEarlyDataAllowed());
        $this->assertEquals(0, $session->getMaxEarlyDataSize());
    }

    /**
     * 测试PSK会话setter方法
     */
    public function testPSKSessionSetters(): void
    {
        $session = new TLS13PSKSession(
            bin2hex(random_bytes(16)),
            0,
            random_bytes(32),
            time()
        );

        // 测试设置PSK身份
        $pskIdentity = bin2hex(random_bytes(16));
        $session->setPskIdentity($pskIdentity);
        $this->assertEquals($pskIdentity, $session->getPskIdentity());

        // 测试设置票据年龄添加值
        $ticketAgeAdd = mt_rand(0, 1000000);
        $session->setTicketAgeAdd($ticketAgeAdd);
        $this->assertEquals($ticketAgeAdd, $session->getTicketAgeAdd());

        // 测试设置票据随机数
        $ticketNonce = random_bytes(16);
        $session->setTicketNonce($ticketNonce);
        $this->assertEquals($ticketNonce, $session->getTicketNonce());

        // 测试设置恢复主密钥
        $resumptionMasterSecret = random_bytes(32);
        $session->setResumptionMasterSecret($resumptionMasterSecret);
        $this->assertEquals($resumptionMasterSecret, $session->getResumptionMasterSecret());
    }

    /**
     * 测试早期数据设置
     */
    public function testEarlyDataSettings(): void
    {
        $session = new TLS13PSKSession(
            bin2hex(random_bytes(16)),
            0,
            random_bytes(32),
            time()
        );

        // 初始状态 - 不允许早期数据
        $this->assertFalse($session->isEarlyDataAllowed());
        $this->assertEquals(0, $session->getMaxEarlyDataSize());

        // 设置允许早期数据
        $session->setEarlyDataAllowed(true);
        $this->assertTrue($session->isEarlyDataAllowed());

        // 设置早期数据最大大小
        $maxSize = 16384;
        $session->setMaxEarlyDataSize($maxSize);
        $this->assertEquals($maxSize, $session->getMaxEarlyDataSize());
        $this->assertTrue($session->isEarlyDataAllowed()); // 设置大小后应自动允许

        // 设置0大小应禁用早期数据
        $session->setMaxEarlyDataSize(0);
        $this->assertEquals(0, $session->getMaxEarlyDataSize());
        $this->assertFalse($session->isEarlyDataAllowed());

        // 显式禁用早期数据
        $session->setMaxEarlyDataSize(16384);
        $this->assertTrue($session->isEarlyDataAllowed());
        $session->setEarlyDataAllowed(false);
        $this->assertFalse($session->isEarlyDataAllowed());
    }
}
