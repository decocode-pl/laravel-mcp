<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Security;

/**
 * Heuristic "does this column NAME look like it could hold PII?" — deliberately
 * BROADER than the masking patterns. It powers `mcp:masking:audit`, whose job is
 * to surface columns the masker misses, so it errs towards over-flagging: a hit
 * is a suggestion for a human to confirm, not a verdict. False positives (a
 * `filename`, an entity `name`) are expected and cheap to dismiss; a false
 * NEGATIVE is the failure this guards against — a bare `ip`, audit `old`/`new`
 * columns, or legacy/non-English names routinely slip a name-based review.
 *
 * Two matchers, to keep signal high on short ambiguous tokens:
 *  - BROAD substrings match anywhere in the name (`customer_email`, `firstname`).
 *  - SHORT tokens match a whole `_`/camelCase-delimited token only, so `old`
 *    flags `old_values` but not `gold`, and `ip` flags `ip`/`client_ip` but not
 *    `description`.
 * Includes common Polish/legacy spellings seen across real client schemas.
 */
final class PiiHeuristic
{
    /** Substrings that, appearing anywhere in a column name, suggest PII. */
    private const BROAD = [
        // Names
        'name', 'imie', 'nazwisko', 'surname', 'firstname', 'lastname', 'fullname',
        'maiden', 'given_name', 'family_name', 'middlename', 'vorname', 'nachname',
        // Contact
        'email', 'mail', 'phone', 'mobile', 'komorka', 'telefon',
        // Address
        'address', 'adres', 'street', 'ulica', 'miasto', 'city', 'postal', 'postcode',
        'post_code', 'kodpocztowy', 'kod_pocztowy', 'zip', 'country', 'wojewodztwo',
        'building', 'mieszkanie', 'apartment', 'apartament',
        // National / financial identifiers
        'pesel', 'passport', 'paszport', 'dowod', 'id_card', 'tax_id', 'iban',
        'bank', 'account', 'konto', 'card', 'swift', 'blik',
        // Secrets & crypto material (a full-schema secret sweep found columns a
        // name-based review misses: `hmac_key`, `p256dh_key`/`auth_key` Web-Push
        // keys, `laravel_session_id`). `key` / `salt` live in SHORT (whole-token)
        // so they flag `*_key` without swallowing `monkey`/`turkey`.
        'password', 'passwd', 'haslo', 'secret', 'token', 'api_key', 'apikey',
        'private_key', 'signature', 'user_agent', 'hmac', 'cipher', 'nonce',
        'credential',
        // Demographic
        'birth', 'urodzen', 'gender', 'nationality', 'obywatelstwo',
        // Free-form fields that routinely carry PII in practice
        'obdarowany', 'pasazer', 'kierowca', 'driver', 'recipient', 'odbiorca',
        'nadawca', 'sender', 'firma', 'company', 'notka', 'komentarz', 'comment',
        'tresc', 'wiadomosc', 'message', 'greeting', 'zyczenia', 'wishes', 'delivery',
        'geolocation', 'latitude', 'longitude',
    ];

    /** Whole-token matches — too short/ambiguous to match as a substring. */
    private const SHORT = [
        'ip', 'old', 'new', 'age', 'dob', 'geo', 'lat', 'lng', 'lon',
        'nip', 'ssn', 'vat', 'regon', 'cvv', 'cvc', 'pin', 'plec', 'tel', 'fax', 'gsm',
        'key', 'salt', 'jwt', 'otp', 'session', 'hash',
    ];

    public static function looksLikePii(string $column): bool
    {
        // Split camelCase before lowercasing so `oldValue` tokenises to old, value.
        $normalized = strtolower((string) preg_replace('/(?<=[a-z0-9])(?=[A-Z])/', '_', $column));

        foreach (self::BROAD as $needle) {
            if (str_contains($normalized, $needle)) {
                return true;
            }
        }

        foreach (array_filter((array) preg_split('/[^a-z0-9]+/', $normalized)) as $token) {
            if (in_array($token, self::SHORT, true)) {
                return true;
            }
        }

        return false;
    }
}
