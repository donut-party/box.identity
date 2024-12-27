(ns donut.box.identity.google-auth-endpoint
  (:require
   [clojure.walk :as walk]
   [donut.box.identity.identity-endpoint :as diie]
   [donut.box.identity.identity-store :as diis]
   [donut.endpoint.route-group :as derg]
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
                               walk/keywordize-keys)]
    (and (= google-client-id (:aud verified-token))
         (#{"https://accounts.google.com" "accounts.google.com"}
          (:iss verified-token))
         verified-token)))


(defn- identity-provider-authenticated! [datasource verified-token user]
  [datasource verified-token user]
  (or (diis/-user-by-email datasource (:email verified-token))
      (diis/-insert-user! datasource user)))

(defn handle-verify-token-success
  [datasource verified-token user]
  (-> datasource
      (identity-provider-authenticated! verified-token user)
      diie/auth-success-response))

(defn handle-verify-token-failure
  []
  {:status 500})

(defn default-verified-token->user
  [{:keys [email name given_name family_name]}]
  {:user/email       email
   :user/name        name
   :user/given-name  given_name
   :user/family-name family_name})

(defn handle-verify-token
  [{{:keys [google-id-token-verifier
            google-client-id
            verified-token->user
            datasource]} :dependencies
    :keys [all-params]}]
  {:pre [google-id-token-verifier google-client-id datasource]}
  (if-let [verified-token (verify-google-token google-id-token-verifier
                                               google-client-id
                                               (:credential all-params))]
    (handle-verify-token-success datasource
                                 verified-token
                                 (verified-token->user verified-token))
    (handle-verify-token-failure)))

(def routes
  [["/verify-token"
    {:name :donut.endpoint.identity.google-auth/validate-token
     :post {:handler handle-verify-token}
     :google-id-token-verifier (ds/local-ref [:google-id-token-verifier])
     :google-client-id (ds/local-ref [:google-client-id])
     :verified-token->user (ds/local-ref [:verified-token->user])}]])

(defn google-auth-route-group
  [& [components]]
  (derg/route-group
   {:routes                   routes
    :path-prefix              "/identity/google-auth"
    :google-id-token-verifier GoogleIdTokenVerifierComponent
    :google-client-id         (ds/ref [:env :google-client-id])
    :verified-token->user     default-verified-token->user}
   components))
