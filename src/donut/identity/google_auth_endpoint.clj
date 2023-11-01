(ns donut.identity.google-auth-endpoint
  (:require
   [clojure.walk :as walk]
   [donut.endpoint.route-group :as derg]
   [donut.identity.identity-endpoint :as diie]
   [donut.identity.identity-store :as diis]
   [donut.system :as ds])
  (:import
   [com.google.api.client.googleapis.auth.oauth2
    GoogleIdTokenVerifier$Builder]
   [com.google.api.client.googleapis.javanet GoogleNetHttpTransport]
   [com.google.api.client.json.gson GsonFactory]
   [java.util Collections]))

(defn google-verifier
  [google-client-id]
  (let [builder (GoogleIdTokenVerifier$Builder.
                 (GoogleNetHttpTransport/newTrustedTransport)
                 (GsonFactory.))]
    (.setAudience builder (Collections/singletonList google-client-id))
    (.build builder)))

(def GoogleIdTokenVerifierComponent
  #::ds{:start  (fn google-id-token-verifier-component-start
                  [opts]
                  (-> opts
                      ::ds/config
                      :google-client-id
                      google-verifier))
        :config {:google-client-id (ds/local-ref [:google-client-id])}
        :pre-start-schema [:map [:google-client-id string?]]})

(defn verify-google-token
  [verifier google-client-id token]
  (let [verified-token (some-> verifier
                               (.verify token)
                               .getPayload
                               (#(into {} %))
                               walk/keywordize-keys
                               (select-keys [:aud :email :email_verified :exp :iat :iss]))]
    (and (= google-client-id (:aud verified-token))
         (#{"https://accounts.google.com" "accounts.google.com"}
          (:iss verified-token))
         verified-token)))


(defn- identity-provider-authenticated! [datasource email]
  [datasource email]
  (or (diis/-user-by-email datasource email)
      (diis/-insert-user! datasource {:user/email email})))

(defn handle-verify-token-success
  [datasource email]
  (-> datasource
      (identity-provider-authenticated! email)
      diie/auth-success-response))

(defn handle-verify-token-failure
  []
  {:status 500})

(defn handle-verify-token
  [{{:keys [google-id-token-verifier google-client-id datasource]} :dependencies
    :keys [all-params]}]
  {:pre [google-id-token-verifier google-client-id datasource]}
  (if-let [verified-token (verify-google-token google-id-token-verifier
                                               google-client-id
                                               (:credential all-params))]
    (handle-verify-token-success datasource (:email verified-token))
    (handle-verify-token-failure)))

(def routes
  [["/verify-token"
    {:name :donut.endpoint.identity.google-auth/validate-token
     :post {:handler handle-verify-token}
     :google-id-token-verifier (ds/local-ref [:google-id-token-verifier])
     :google-client-id (ds/local-ref [:google-client-id])}]])

(defn google-auth-route-group
  [& [components]]
  (derg/route-group
   (merge {:routes routes
           :group-path "/identity/google-auth"
           :google-id-token-verifier GoogleIdTokenVerifierComponent
           :google-client-id (ds/ref [:env :google-client-id])}
          components)))
