-- Keep the original sandbox profile for local builds and accept the
-- production profile used by TestFlight. Both are bound to the same signed
-- Steelbeach bundle identity; the gateway selects APNs environment by profile.
ALTER TABLE push_gateway_installations
    DROP CONSTRAINT push_gateway_installations_app_profile_check;
ALTER TABLE push_gateway_installations
    ADD CONSTRAINT push_gateway_installations_app_profile_check
    CHECK (app_profile IN (
        'buzz-ios-dogfood',
        'buzz-ios-sandbox',
        'buzz-ios-production'
    ));
