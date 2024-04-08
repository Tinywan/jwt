<?php
/**
 * @desc JWT
 * @author Tinywan(ShaoBo Wan)
 * @date 2024/11/11 15:16
 */

declare(strict_types=1);

namespace Tinywan;

class Jwt
{
    /**string $secretKey*/
    private string $secretKey;

    /**
     * @desc 构架函数
     * @param string $secretKey
     * @author Tinywan(ShaoBo Wan)
     */
    public function __construct(string $secretKey)
    {
        $this->secretKey = $secretKey;
    }

    /**
     * @desc 创建JWT
     * @param array $payload
     * @return string
     * @author Tinywan(ShaoBo Wan)
     */
    public function createToken(array $payload): string
    {
        $base64UrlHeader = $this->base64UrlEncode(json_encode(["alg" => "HS256", "typ" => "JWT"]));
        $base64UrlPayload = $this->base64UrlEncode(json_encode($payload));
        $base64UrlSignature = hash_hmac('sha256', $base64UrlHeader . '.' . $base64UrlPayload, $this->secretKey, true);
        $base64UrlSignature = $this->base64UrlEncode($base64UrlSignature);
        return $base64UrlHeader . '.' . $base64UrlPayload . '.' . $base64UrlSignature;
    }


    /**
     * @desc 验证JWT
     * @param string $token
     * @return bool
     */
    public function validateToken(string $token): bool
    {
        list($base64UrlHeader, $base64UrlPayload, $base64UrlSignature) = explode('.', $token);
        $signature = $this->base64UrlDecode($base64UrlSignature);
        $expectedSignature = hash_hmac('sha256', $base64UrlHeader . '.' . $base64UrlPayload, $this->secretKey, true);

        return hash_equals($signature, $expectedSignature);
    }


    /**
     * @desc 解码JWT
     * @param string $token
     * @return array
     */
    public function decodeToken(string $token): array
    {
        list(, $base64UrlPayload, ) = explode('.', $token);
        $payload = $this->base64UrlDecode($base64UrlPayload);
        return json_decode($payload, true);
    }

    /**
     * @desc base64_encode 编码
     * @param string $data
     * @return string
     * @author Tinywan(ShaoBo Wan)
     */
    private function base64UrlEncode(string $data): string
    {
        $base64 = base64_encode($data);
        $base64Url = strtr($base64, '+/', '-_');
        return rtrim($base64Url, '=');
    }

    /**
     * @desc base64_encode 解码
     * @param string $data
     * @return string
     * @author Tinywan(ShaoBo Wan)
     */
    private function base64UrlDecode(string $data): string
    {
        $base64 = strtr($data, '-_', '+/');
        $base64Padded = str_pad($base64, strlen($base64) % 4, '=', STR_PAD_RIGHT);
        return base64_decode($base64Padded);
    }
}