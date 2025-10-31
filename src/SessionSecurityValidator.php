<?php

declare(strict_types=1);

namespace Tourze\TLSSession;

use Tourze\TLSSession\Exception\InvalidArgumentException;

/**
 * 会话安全参数验证器
 *
 * 用于验证恢复会话的安全参数，确保不会降级安全性或使用不兼容的加密套件
 */
class SessionSecurityValidator
{
    /**
     * 验证TLS 1.2会话参数
     *
     * @param TLSSession $session             要验证的会话
     * @param string     $proposedCipherSuite 客户端提议的加密套件
     * @param int        $proposedTlsVersion  客户端提议的TLS版本
     * @param bool       $allowDowngrade      是否允许降级到较低的安全性，默认为false
     *
     * @return bool 验证结果
     */
    public function validateTLS12Session(
        TLSSession $session,
        string $proposedCipherSuite,
        int $proposedTlsVersion,
        bool $allowDowngrade = false,
    ): bool {
        // 验证加密套件
        if ($session->getCipherSuite() !== $proposedCipherSuite) {
            return false;
        }

        // 验证TLS版本（不允许降级，除非明确指定）
        if (!$allowDowngrade && $proposedTlsVersion < $session->getTlsVersion()) {
            return false;
        }

        return true;
    }

    /**
     * 验证TLS 1.3 PSK会话参数
     *
     * @param TLS13PSKSession $session             要验证的PSK会话
     * @param string          $proposedCipherSuite 客户端提议的加密套件
     * @param bool            $fuzzyMatch          是否使用模糊匹配（如不区分大小写）
     *
     * @return bool 验证结果
     */
    public function validateTLS13PSK(
        TLS13PSKSession $session,
        string $proposedCipherSuite,
        bool $fuzzyMatch = false,
    ): bool {
        if ($fuzzyMatch) {
            return 0 === strcasecmp($session->getCipherSuite(), $proposedCipherSuite);
        }

        return $session->getCipherSuite() === $proposedCipherSuite;
    }

    /**
     * 根据服务器配置选项验证会话
     *
     * @param SessionInterface $session       要验证的会话
     * @param array<string, mixed> $serverOptions 服务器配置选项
     *
     * @return bool 验证结果
     */
    public function validateSessionAgainstServerOptions(
        SessionInterface $session,
        array $serverOptions,
    ): bool {
        $config = $this->parseServerOptions($serverOptions);

        if (!$this->validateTlsVersion($session, $config)) {
            return false;
        }

        return $this->validateCipherSuite($session, $config);
    }

    /**
     * 解析服务器配置选项
     *
     * @param array<string, mixed> $serverOptions 服务器配置选项
     *
     * @return array<string, mixed> 解析后的配置
     */
    private function parseServerOptions(array $serverOptions): array
    {
        return [
            'allowDowngrade' => $serverOptions['allowDowngrade'] ?? false,
            'requireExactMatch' => $serverOptions['requireExactMatch'] ?? true,
            'minimumTlsVersion' => $serverOptions['minimumTlsVersion'] ?? 0x0303,
            'allowedCipherSuites' => $serverOptions['allowedCipherSuites'] ?? [],
        ];
    }

    /**
     * 验证TLS版本
     *
     * @param SessionInterface $session 会话
     * @param array<string, mixed> $config  配置
     *
     * @return bool 验证结果
     */
    private function validateTlsVersion(SessionInterface $session, array $config): bool
    {
        if (!$session instanceof TLSSession) {
            return true;
        }

        $allowDowngrade = $config['allowDowngrade'];
        $minimumTlsVersion = $config['minimumTlsVersion'];

        if (!is_bool($allowDowngrade)) {
            throw new InvalidArgumentException('allowDowngrade必须是布尔值');
        }
        if (!is_int($minimumTlsVersion)) {
            throw new InvalidArgumentException('minimumTlsVersion必须是整数');
        }

        if (!$allowDowngrade && $session->getTlsVersion() < $minimumTlsVersion) {
            return false;
        }

        return true;
    }

    /**
     * 验证加密套件
     *
     * @param SessionInterface $session 会话
     * @param array<string, mixed> $config  配置
     *
     * @return bool 验证结果
     */
    private function validateCipherSuite(SessionInterface $session, array $config): bool
    {
        if ([] === $config['allowedCipherSuites']) {
            return true;
        }

        $sessionCipherSuite = $session->getCipherSuite();

        $requireExactMatch = $config['requireExactMatch'];
        if (!is_bool($requireExactMatch)) {
            throw new InvalidArgumentException('requireExactMatch必须是布尔值');
        }

        if ($requireExactMatch) {
            return in_array($sessionCipherSuite, $config['allowedCipherSuites'], true);
        }

        return $this->fuzzyMatchCipherSuite($sessionCipherSuite, $config['allowedCipherSuites']);
    }

    /**
     * 模糊匹配加密套件
     *
     * @param string   $sessionCipherSuite  会话加密套件
     * @param string[] $allowedCipherSuites 允许的加密套件列表
     *
     * @return bool 匹配结果
     */
    private function fuzzyMatchCipherSuite(string $sessionCipherSuite, array $allowedCipherSuites): bool
    {
        foreach ($allowedCipherSuites as $allowedSuite) {
            if (0 === strcasecmp($sessionCipherSuite, $allowedSuite)) {
                return true;
            }
        }

        return false;
    }
}
