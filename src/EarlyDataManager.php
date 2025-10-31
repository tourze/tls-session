<?php

declare(strict_types=1);

namespace Tourze\TLSSession;

use Tourze\TLSSession\Exception\InvalidArgumentException;

/**
 * TLS 1.3早期数据（0-RTT）管理器
 *
 * 用于处理TLS 1.3中的0-RTT数据，包括存储、验证和防止重放攻击
 */
class EarlyDataManager
{
    /** @var array<string, array{data: string, pskIdentity: string, timestamp: int}> */
    private array $earlyData = [];

    /** @var array<int, string> */
    private array $usedEarlyDataIds = [];
    private const SESSION_LIFETIME = 3600; // 默认会话有效期为1小时（秒）

    /**
     * 存储早期数据，并返回早期数据ID
     *
     * @param TLS13PSKSession $session 关联的PSK会话
     * @param string          $data    要存储的早期数据
     *
     * @return string 早期数据ID，用于后续验证
     *
     * @throws InvalidArgumentException 如果早期数据大小超过最大允许值
     */
    public function storeEarlyData(TLS13PSKSession $session, string $data): string
    {
        // 检查早期数据大小是否超过最大允许值
        if (strlen($data) > $session->getMaxEarlyDataSize()) {
            throw new InvalidArgumentException('Early data size exceeds maximum allowed size');
        }

        // 生成唯一的早期数据ID
        $earlyDataId = bin2hex(random_bytes(16));

        // 存储早期数据
        $this->earlyData[$earlyDataId] = [
            'data' => $data,
            'pskIdentity' => $session->getPskIdentity(),
            'timestamp' => time(),
        ];

        return $earlyDataId;
    }

    /**
     * 获取并验证早期数据
     *
     * 验证通过后，数据将被标记为已使用，以防止重放攻击
     *
     * @param TLS13PSKSession $session     关联的PSK会话
     * @param string          $earlyDataId 早期数据ID
     *
     * @return string|null 验证成功则返回数据，否则返回null
     */
    public function getAndValidateEarlyData(TLS13PSKSession $session, string $earlyDataId): ?string
    {
        // 检查早期数据ID是否存在
        if (!isset($this->earlyData[$earlyDataId])) {
            return null;
        }

        // 检查早期数据是否已被使用（防止重放攻击）
        if (in_array($earlyDataId, $this->usedEarlyDataIds, true)) {
            return null;
        }

        $earlyDataInfo = $this->earlyData[$earlyDataId];

        // 检查PSK身份是否匹配
        if ($earlyDataInfo['pskIdentity'] !== $session->getPskIdentity()) {
            return null;
        }

        // 检查会话是否已过期
        if ($this->isSessionExpired($session)) {
            return null;
        }

        // 标记早期数据为已使用
        $this->usedEarlyDataIds[] = $earlyDataId;

        return $earlyDataInfo['data'];
    }

    /**
     * 清除所有早期数据
     */
    public function clearAllEarlyData(): void
    {
        $this->earlyData = [];
        $this->usedEarlyDataIds = [];
    }

    /**
     * 检查会话是否过期
     */
    private function isSessionExpired(TLS13PSKSession $session): bool
    {
        $expiryTime = $session->getCreationTime() + self::SESSION_LIFETIME;

        return time() > $expiryTime;
    }
}
