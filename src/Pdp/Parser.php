<?php
    /**
     * PHP Domain Parser: Public Suffix List based URL parsing.
     *
     * @link      http://github.com/jeremykendall/php-domain-parser for the canonical source repository
     *
     * @copyright Copyright (c) 2014 Jeremy Kendall (http://about.me/jeremykendall)
     * @license   http://github.com/jeremykendall/php-domain-parser/blob/master/LICENSE MIT License
     */

    namespace Pdp;

    use Pdp\Uri\Url;
    use Pdp\Uri\Url\Host;

    /**
     * Parser.
     *
     * This class is reponsible for Public Suffix List based url parsing
     */
    class Parser
    {
        /**
         * @var string RFC 3986 compliant scheme regex pattern
         *
         * @see https://tools.ietf.org/html/rfc3986#section-3.1
         */
        public const SCHEME_PATTERN = '#^([a-zA-Z][a-zA-Z0-9+\-.]*)://#';

        /**
         * @var string IP address regex pattern
         */
        public const IP_ADDRESS_PATTERN = '/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/';

        /**
         * @var PublicSuffixList Public Suffix List
         */
        protected $publicSuffixList;

        /**
         * @var bool Whether or not a host part has been normalized
         */
        protected $isNormalized = false;

        /**
         * Public constructor.
         *
         * @codeCoverageIgnore
         *
         * @param PublicSuffixList $publicSuffixList Instance of PublicSuffixList
         */
        public function __construct(PublicSuffixList $publicSuffixList)
        {
            $this->publicSuffixList = $publicSuffixList;
        }

        /**
         * Parses url.
         *
         * @param string $url Url to parse
         *
         * @return Url Object representation of url
         */
        public function parseUrl(string $url)
        {
            $elem = [
                'scheme'   => null,
                'user'     => null,
                'pass'     => null,
                'host'     => null,
                'port'     => null,
                'path'     => null,
                'query'    => null,
                'fragment' => null,
            ];

            if (preg_match(self::SCHEME_PATTERN, $url) === 0) {
                // Wacky scheme required to overcome parse_url behavior in PHP lt 5.4.7
                // See https://github.com/jeremykendall/php-domain-parser/issues/49
                $url = 'php-lt-5.4.7-hack://' . preg_replace('#^//#', '', $url, 1);
            }

            $parts = $this->pdp_parse_url($url);

            if ($parts === false) {
                throw new \InvalidArgumentException(sprintf('Invalid url %s', $url));
            }

            if ($parts['scheme'] === 'php-lt-5.4.7-hack') {
                // Remove wacky scheme required to overcome parse_url behavior in PHP lt 5.4.7
                // See https://github.com/jeremykendall/php-domain-parser/issues/49
                $parts['scheme'] = null;
            }

            $elem = (array) $parts + $elem;

            $host = $this->parseHost($parts['host']);

            return new Url(
                $elem['scheme'],
                $elem['user'],
                $elem['pass'],
                $host,
                $elem['port'],
                $elem['path'],
                $elem['query'],
                $elem['fragment']
            );
        }

        /**
         * UTF-8 aware parse_url() replacement.
         *
         * Taken from php.net manual comments {@link http://php.net/manual/en/function.parse-url.php#114817}
         *
         * @param string $url       The URL to parse
         * @param int $component Specify one of PHP_URL_SCHEME, PHP_URL_HOST,
         *                            PHP_URL_PORT, PHP_URL_USER, PHP_URL_PASS, PHP_URL_PATH, PHP_URL_QUERY or
         *                            PHP_URL_FRAGMENT to retrieve just a specific URL component as a string
         *                            (except when PHP_URL_PORT is given, in which case the return value will
         *                            be an integer).
         *
         * @return array|false|int|string   See parse_url documentation {@link http://us1.php.net/parse_url}
         */
        private function pdp_parse_url(string $url, int $component = -1)
        {
            $pattern = '%([a-zA-Z][a-zA-Z0-9+\-.]*)?(:?//)?([^:/@?&=#\[\]]+)%usD';

            $enc_url = preg_replace_callback(
                $pattern,
                static function ($matches) {
                    $encoded = urlencode($matches[3]);

                    return sprintf('%s%s%s', $matches[1], $matches[2], $encoded);
                },
                $url
            );

            $parts = parse_url($enc_url, $component);

            if ($parts === false) {
                return false;
            }

            if (\is_array($parts)) {
                foreach ($parts as $name => $value) {
                    if ($name === 'scheme') {
                        continue;
                    }

                    $parts[$name] = urldecode($value);
                }
            } else {
                $parts = urldecode($parts);
            }

            return $parts;
        }

        /**
         * Parses host part of url.
         *
         * @param string $host Host part of url
         *
         * @return Host Object representation of host portion of url
         */
        public function parseHost(string $host)
        {
            $host = mb_strtolower($host, 'UTF-8');

            $subdomain = null;
            $registerableDomain = null;
            $publicSuffix = null;

            // Fixes #22: Single label domains are set as Host::$host and all other
            // properties are null.
            // Fixes #43: Ip Addresses should not be parsed
            if ($this->isMutliLabelDomain($host) || !$this->isIpv4Address($host)) {
                $subdomain = $this->getSubdomain($host);
                $registerableDomain = $this->getRegisterableDomain($host);
                $publicSuffix = $this->getPublicSuffix($host);
            }

            return new Host(
                $subdomain,
                $registerableDomain,
                $publicSuffix,
                $host
            );
        }

        /**
         * Get the raw public suffix based on the cached public suffix list file.
         * Return false if the provided suffix is not included in the PSL.
         *
         * @param string $host The host to process
         *
         * @return string|false The suffix or false if suffix not included in the PSL
         */
        protected function getRawPublicSuffix($host)
        {
            $host = $this->normalize($host);

            $parts = array_reverse(explode('.', $host));
            $publicSuffix = [];
            $publicSuffixList = $this->publicSuffixList->getArrayCopy();

            foreach ($parts as $part) {
                if (\array_key_exists($part, $publicSuffixList)
                    && \array_key_exists('!', $publicSuffixList[$part])) {
                    break;
                }

                if (\array_key_exists($part, $publicSuffixList)) {
                    array_unshift($publicSuffix, $part);
                    $publicSuffixList = $publicSuffixList[$part];
                    continue;
                }

                if (\array_key_exists('*', $publicSuffixList)) {
                    array_unshift($publicSuffix, $part);
                    $publicSuffixList = $publicSuffixList['*'];
                    continue;
                }

                // Avoids improper parsing when $host's subdomain + public suffix ===
                // a valid public suffix (e.g. host 'us.example.com' and public suffix 'us.com')
                //
                // Added by @goodhabit in https://github.com/jeremykendall/php-domain-parser/pull/15
                // Resolves https://github.com/jeremykendall/php-domain-parser/issues/16
                break;
            }

            // If empty, then the suffix is not included in the PSL and is
            // considered "invalid". This also triggers algorithm rule #2: If no
            // rules match, the prevailing rule is "*".
            if (empty($publicSuffix)) {
                return false;
            }

            $suffix = implode('.', array_filter($publicSuffix, 'strlen'));

            return $this->denormalize($suffix);
        }

        /**
         * Returns the public suffix portion of provided host.
         *
         * @param string $host host
         *
         * @return string|null public suffix or null if host does not contain a public suffix
         */
        public function getPublicSuffix(string $host)
        {
            if (strpos($host, '.') === 0) {
                return;
            }

            // Fixes #22: If a single label domain makes it this far (e.g.,
            // localhost, foo, etc.), this stops it from incorrectly being set as
            // the public suffix.
            if (!$this->isMutliLabelDomain($host)) {
                return;
            }

            // Fixes #43
            if ($this->isIpv4Address($host)) {
                return;
            }

            $suffix = $this->getRawPublicSuffix($host);

            // Apply algorithm rule #2: If no rules match, the prevailing rule is "*".
            if ($suffix === false) {
                $parts = array_reverse(explode('.', $host));
                $suffix = array_shift($parts);
            }

            return $suffix;
        }

        /**
         * Is suffix valid?
         *
         * Validity determined by whether or not the suffix is included in the PSL.
         *
         * @param string $host Host part
         *
         * @return bool True is suffix is valid, false otherwise
         */
        public function isSuffixValid($host)
        {
            return $this->getRawPublicSuffix($host) !== false;
        }

        /**
         * Returns registerable domain portion of provided host.
         *
         * Per the test cases provided by Mozilla
         * (http://mxr.mozilla.org/mozilla-central/source/netwerk/test/unit/data/test_psl.txt?raw=1),
         * this method should return null if the domain provided is a public suffix.
         *
         * @param string $host host
         *
         * @return string registerable domain
         */
        public function getRegisterableDomain(string $host)
        {
            if (!str_contains($host, '.')) {
                return;
            }

            $publicSuffix = $this->getPublicSuffix($host);

            if ($publicSuffix === null || $host == $publicSuffix) {
                return;
            }

            $publicSuffixParts = array_reverse(explode('.', $publicSuffix));
            $hostParts = array_reverse(explode('.', $host));
            $registerableDomainParts = $publicSuffixParts + array_slice($hostParts, 0, count($publicSuffixParts) + 1);

            return implode('.', array_reverse($registerableDomainParts));
        }

        /**
         * Returns the subdomain portion of provided host.
         *
         * @param string $host host
         *
         * @return string subdomain
         */
        public function getSubdomain($host)
        {
            $registerableDomain = $this->getRegisterableDomain($host);

            if ($registerableDomain === null || $host === $registerableDomain) {
                return;
            }

            $registerableDomainParts = array_reverse(explode('.', $registerableDomain));

            $host = $this->normalize($host);

            $hostParts = array_reverse(explode('.', $host));
            $subdomainParts = array_slice($hostParts, count($registerableDomainParts));

            $subdomain = implode('.', array_reverse($subdomainParts));

            return $this->denormalize($subdomain);
        }

        /**
         * If a URL is not punycoded, then it may be an IDNA URL, so it must be
         * converted to ASCII. Performs conversion and sets flag.
         *
         * @param string $part Host part
         *
         * @return string Host part, transformed if not punycoded
         */
        protected function normalize($part)
        {
            $punycoded = (str_contains($part, 'xn--'));

            if ($punycoded === false) {
                $part = idn_to_ascii($part);
                $this->isNormalized = true;
            }

            return strtolower($part);
        }

        /**
         * Converts any normalized part back to IDNA. Performs conversion and
         * resets flag.
         *
         * @param string $part Host part
         *
         * @return string Denormalized host part
         */
        protected function denormalize($part)
        {
            if ($this->isNormalized === true) {
                $part = idn_to_utf8($part);
                $this->isNormalized = false;
            }

            return $part;
        }

        /**
         * Tests host for presence of '.'.
         *
         * Related to #22
         *
         * @param string $host Host part of url
         *
         * @return bool True if multi-label domain, false otherwise
         */
        protected function isMutliLabelDomain(string $host): bool
        {
            return str_contains($host, '.');
        }

        /**
         * Tests host to determine if it is an IP address.
         *
         * Related to #43
         *
         * @param string $host Host part of url
         *
         * @return bool True if host is an ip address, false otherwise
         */
        protected function isIpv4Address($host)
        {
            return preg_match(self::IP_ADDRESS_PATTERN, $host) === 1;
        }
    }