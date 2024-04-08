<?php
/**
 * @desc PHP JWT
 * @author Tinywan(ShaoBo Wan)
 * @date 2024/04/10 15:16
 */

declare(strict_types=1);

namespace Tinywan;

class Jwt
{
    /**string */
    private string $secretKey;

    /**
     * @param string $secretKey
     * @author Tinywan(ShaoBo Wan)
     */
    public function __construct(string $secretKey)
    {
        $this->secretKey = $secretKey;
    }

    /**
     * @desc create token
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
     * @desc validate token
     * @param string $token
     * @return bool
     * @author Tinywan(ShaoBo Wan)
     */
    public function validateToken(string $token): bool
    {
        list($base64UrlHeader, $base64UrlPayload, $base64UrlSignature) = explode('.', $token);
        $signature = $this->base64UrlDecode($base64UrlSignature);
        $expectedSignature = hash_hmac('sha256', $base64UrlHeader . '.' . $base64UrlPayload, $this->secretKey, true);

        return hash_equals($signature, $expectedSignature);
    }

    /**
     * @desc decode token
     * @param string $token
     * @return array
     * @author Tinywan(ShaoBo Wan)
     */
    public function decodeToken(string $token): array
    {
        list(, $base64UrlPayload,) = explode('.', $token);
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