<?php

declare(strict_types=1);

namespace Tourze\TLSSession\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSSession\EarlyDataManager;
use Tourze\TLSSession\TLS13PSKSession;

/**
 * @internal
 */
#[CoversClass(EarlyDataManager::class)]
final class EarlyDataManagerTest extends TestCase
{
    private EarlyDataManager $manager;

    protected function setUp(): void
    {
        parent::setUp();

        $this->manager = new EarlyDataManager();
    }

    /**
     * 测试存储早期数据
     */
    public function testStoreEarlyData(): void
    {
        // 创建PSK会话
        $pskIdentity = bin2hex(random_bytes(16));
        $session = new TLS13PSKSession(
            bin2hex(random_bytes(16)),
            0,
            random_bytes(32),
            time(),
            $pskIdentity
        );

        // 设置早期数据允许大小
        $maxSize = 16384;
        $session->setMaxEarlyDataSize($maxSize);

        // 测试数据
        $data = random_bytes(1024);

        // 存储早期数据
        $earlyDataId = $this->manager->storeEarlyData($session, $data);

        $this->assertNotEmpty($earlyDataId);
    }

    /**
     * 测试验证并获取早期数据
     */
    public function testGetAndValidateEarlyData(): void
    {
        // 创建PSK会话
        $pskIdentity = bin2hex(random_bytes(16));
        $session = new TLS13PSKSession(
            bin2hex(random_bytes(16)),
            0,
            random_bytes(32),
            time(),
            $pskIdentity
        );

        // 设置早期数据允许大小
        $maxSize = 16384;
        $session->setMaxEarlyDataSize($maxSize);

        // 测试数据
        $data = random_bytes(1024);

        // 存储早期数据
        $earlyDataId = $this->manager->storeEarlyData($session, $data);

        // 验证并获取早期数据
        $retrievedData = $this->manager->getAndValidateEarlyData($session, $earlyDataId);

        $this->assertEquals($data, $retrievedData);
    }

    /**
     * 测试当PSK身份不匹配时，验证应失败
     */
    public function testValidationFailsWithDifferentPSKIdentity(): void
    {
        // 创建第一个PSK会话
        $pskIdentity1 = bin2hex(random_bytes(16));
        $session1 = new TLS13PSKSession(
            bin2hex(random_bytes(16)),
            0,
            random_bytes(32),
            time(),
            $pskIdentity1
        );
        $session1->setMaxEarlyDataSize(16384);

        // 创建第二个PSK会话（不同的身份）
        $pskIdentity2 = bin2hex(random_bytes(16));
        $session2 = new TLS13PSKSession(
            bin2hex(random_bytes(16)),
            0,
            random_bytes(32),
            time(),
            $pskIdentity2
        );
        $session2->setMaxEarlyDataSize(16384);

        // 存储早期数据（使用第一个会话）
        $data = random_bytes(1024);
        $earlyDataId = $this->manager->storeEarlyData($session1, $data);

        // 使用第二个会话尝试验证早期数据
        $retrievedData = $this->manager->getAndValidateEarlyData($session2, $earlyDataId);

        $this->assertNull($retrievedData);
    }

    /**
     * 测试防止重放攻击
     */
    public function testPreventReplayAttack(): void
    {
        // 创建PSK会话
        $pskIdentity = bin2hex(random_bytes(16));
        $session = new TLS13PSKSession(
            bin2hex(random_bytes(16)),
            0,
            random_bytes(32),
            time(),
            $pskIdentity
        );
        $session->setMaxEarlyDataSize(16384);

        // 存储早期数据
        $data = random_bytes(1024);
        $earlyDataId = $this->manager->storeEarlyData($session, $data);

        // 第一次验证应成功
        $firstRetrieve = $this->manager->getAndValidateEarlyData($session, $earlyDataId);
        $this->assertEquals($data, $firstRetrieve);

        // 第二次验证应失败（防止重放）
        $secondRetrieve = $this->manager->getAndValidateEarlyData($session, $earlyDataId);
        $this->assertNull($secondRetrieve);
    }

    /**
     * 测试数据大小超过限制时应抛出异常
     */
    public function testThrowsExceptionWhenDataSizeExceedsLimit(): void
    {
        // 创建PSK会话并设置较小的早期数据限制
        $session = new TLS13PSKSession(
            bin2hex(random_bytes(16)),
            0,
            random_bytes(32),
            time(),
            bin2hex(random_bytes(16))
        );
        $session->setMaxEarlyDataSize(1024);

        // 创建超过限制的数据
        $largeData = random_bytes(2048);

        $this->expectException(\InvalidArgumentException::class);
        $this->manager->storeEarlyData($session, $largeData);
    }

    /**
     * 测试清除所有早期数据
     */
    public function testClearAllEarlyData(): void
    {
        // 创建PSK会话
        $pskIdentity = bin2hex(random_bytes(16));
        $session = new TLS13PSKSession(
            bin2hex(random_bytes(16)),
            0,
            random_bytes(32),
            time(),
            $pskIdentity
        );
        $session->setMaxEarlyDataSize(16384);

        // 存储早期数据
        $data = random_bytes(1024);
        $earlyDataId = $this->manager->storeEarlyData($session, $data);

        // 确认数据可以被获取
        $retrievedData = $this->manager->getAndValidateEarlyData($session, $earlyDataId);
        $this->assertEquals($data, $retrievedData);

        // 清除所有早期数据
        $this->manager->clearAllEarlyData();

        // 确认数据不能被获取
        $retrievedDataAfterClear = $this->manager->getAndValidateEarlyData($session, $earlyDataId);
        $this->assertNull($retrievedDataAfterClear);
    }
}
