<?php

declare(strict_types=1);

namespace Tourze\TLSSession;

/**
 * TLS 1.3 PSK会话管理器
 *
 * 负责创建、验证和管理TLS 1.3中的PSK会话恢复
 */
class TLS13PSKSessionManager extends InMemorySessionManager
{
    /**
     * 会话存储
     *
     * @var array<string, TLS13PSKSession> PSK身份到会话的映射
     */
    private array $pskSessions = [];

    /**
     * 票据年龄添加值
     */
    private int $ticketAgeAdd;

    /**
     * 早期数据支持
     */
    private bool $allowEarlyData = false;

    /**
     * 早期数据最大大小
     */
    private int $maxEarlyDataSize = 0;

    /**
     * 构造函数
     */
    public function __construct()
    {
        // 生成随机的票据年龄添加值 (使用mt_rand代替random_int避免熵不足问题)
        $this->ticketAgeAdd = mt_rand(0, mt_getrandmax()) % (1 << 30);
    }

    /**
     * 创建PSK会话
     *
     * @param int    $cipherSuite            加密套件
     * @param string $masterSecret           主密钥
     * @param string $resumptionMasterSecret 恢复主密钥
     * @param string $ticketNonce            票据随机数
     *
     * @return TLS13PSKSession 会话对象
     */
    public function createPSKSession(
        int $cipherSuite,
        string $masterSecret,
        string $resumptionMasterSecret,
        string $ticketNonce = '',
    ): TLS13PSKSession {
        // 生成PSK身份（作为唯一标识符）
        $pskIdentity = bin2hex(random_bytes(16));

        // 生成随机票据随机数（如果未提供）
        if ('' === $ticketNonce) {
            $ticketNonce = random_bytes(16);
        }

        $session = new TLS13PSKSession(
            bin2hex(random_bytes(16)), // 会话ID
            $cipherSuite,
            $masterSecret,
            time(),
            $pskIdentity,
            $this->ticketAgeAdd,
            $ticketNonce,
            $resumptionMasterSecret
        );

        // 设置早期数据参数
        if ($this->allowEarlyData) {
            $session->setEarlyDataAllowed(true);
            $session->setMaxEarlyDataSize($this->maxEarlyDataSize);
        }

        // 存储会话
        $this->pskSessions[$pskIdentity] = $session;

        return $session;
    }

    /**
     * 通过PSK身份获取会话
     *
     * @param string $pskIdentity PSK身份
     *
     * @return TLS13PSKSession|null 会话对象，不存在则返回null
     */
    public function getSessionByPskIdentity(string $pskIdentity): ?TLS13PSKSession
    {
        if (!isset($this->pskSessions[$pskIdentity])) {
            return null;
        }

        $session = $this->pskSessions[$pskIdentity];

        // 检查会话是否有效
        if (!$session->isValid()) {
            unset($this->pskSessions[$pskIdentity]);

            return null;
        }

        return $session;
    }

    /**
     * 移除PSK会话
     *
     * @param string $pskIdentity PSK身份
     *
     * @return bool 是否成功
     */
    public function removePSKSession(string $pskIdentity): bool
    {
        if (isset($this->pskSessions[$pskIdentity])) {
            unset($this->pskSessions[$pskIdentity]);

            return true;
        }

        return false;
    }

    /**
     * 清理过期的PSK会话
     *
     * @return int 清理的会话数量
     */
    public function cleanExpiredPSKSessions(): int
    {
        $count = 0;
        $currentTime = time();

        foreach ($this->pskSessions as $pskIdentity => $session) {
            if (!$session->isValid($currentTime)) {
                unset($this->pskSessions[$pskIdentity]);
                ++$count;
            }
        }

        return $count;
    }

    /**
     * 设置是否支持早期数据
     *
     * @param bool $allowEarlyData 是否支持
     */
    public function setEarlyDataAllowed(bool $allowEarlyData): void
    {
        $this->allowEarlyData = $allowEarlyData;
    }

    /**
     * 设置早期数据最大大小
     *
     * @param int $maxEarlyDataSize 最大大小
     */
    public function setMaxEarlyDataSize(int $maxEarlyDataSize): void
    {
        $this->maxEarlyDataSize = $maxEarlyDataSize;
        $this->allowEarlyData = ($maxEarlyDataSize > 0);
    }

    /**
     * 清理所有会话
     */
    public function cleanAllSessions(): void
    {
        parent::cleanExpiredSessions();
        $this->pskSessions = [];
    }
}
