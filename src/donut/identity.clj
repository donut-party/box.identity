(ns donut.identity
  (:require
   [buddy.hashers :as buddy-hashers]
   [donut.email :as de]
   [donut.endpoint.response :as der]
   [donut.endpoint.route-group :as derg]
   [donut.hooked :as hooked]
   [donut.sugar.utils :as dsu]
   [donut.system :as ds]
   [nano-id.core :as nano-id]
   [reitit.core :as r]))

(def DEFAULT-TOKEN-MAX-AGE
  "sixty minutes"
  (* 60 20))

;;---
;; helpers
;;---

(defn- current-time-seconds
  []
  (quot (System/currentTimeMillis) 1000))

(defn- token-expired?
  [user token-max-age]
  (> (- (current-time-seconds)
        (:user/password_reset_token_created_at user))
     token-max-age))

;;---
;; data store interactions
;;---

(defprotocol IdentityStore
  (user-by-email* [datasource email])
  (user-signup* [datasource user])
  (user-by-credentials* [datasource credentials])
  (user-by-password-reset-token* [datasource token])
  (create-reset-password-token* [datasource token])
  (reset-password* [datasource password-reset]))

(defn user-by-credentials
  [datasource {:keys [:user/password] :as credentials}]
  (let [user (user-by-credentials* datasource credentials)]
    (and user
         (not-empty password)
         (:valid (buddy-hashers/verify password (:user/password_hash user)))
         user)))

(defn user-signup
  [datasource user]
  (user-signup* datasource (-> user
                               (dissoc :user/password)
                               (assoc :user/password_hash (buddy-hashers/encrypt (:user/password user))))))

(defn create-reset-password-token
  [datasource user]
  (create-reset-password-token* datasource
                                (assoc user
                                       :user/password_reset_token (nano-id/nano-id 10)
                                       :user/password_reset_token_created_at (current-time-seconds))))

(defn reset-password
  [datasource {:keys [token token-max-age] :as password-reset}]
  (when-let [user (user-by-password-reset-token* datasource token)]
    (if (token-expired? user token-max-age)
      :expired
      (reset-password* datasource password-reset))))

(defn- valid-token?
  [datasource token token-max-age]
  (let [user (user-by-password-reset-token* datasource token)]
    (and user (not (token-expired? user token-max-age)))))

;;---
;; hooks
;;---

(hooked/defhook ::signup-handler.validation-errors
  "Called when a signup fails because of validation errors"
  [:map [:errors :map]])
(hooked/defhook ::signup-handler.signup-success
  "Called when a user signup is successful"
  [:map [:user :map]])
(hooked/defhook ::create-reset-password-token-handler.email-sent
  "")

;;---
;; ring
;;---

(defn session-identity
  [user]
  (select-keys user [:user/email]))

(defn auth-success-response
  [user]
  (let [identity (session-identity user)]
    {:status  200
     :body    [[:auth {:identity identity}]]
     :session {:identity identity}}))

(defn UserSignupSchema
  [datasource]
  [:and
   [:map
    [:user/email
     [:re {:description "https://github.com/gfredericks/test.chuck/issues/46"
           :gen/fmap '(constantly "random@example.com")
           :error/message "Please enter an email address"}
      #"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}$"]]
    [:user/password  [:string {:min 8}]]]
   [:fn {:error/message "email address already taken"
         :error/path    [:user/email]}
    (fn [{:keys [:user/email]}]
      (not (user-by-email* datasource email)))]])

(defn signup-handler
  [{{:keys [datasource]} :dependencies
    :keys [all-params]
    :as req}]
  (if-let [errors (dsu/feedback (UserSignupSchema datasource) all-params)]
    (do
      (hooked/call ::signup-handler.validation-errors (assoc req :errors errors))
      (der/errors-response errors all-params))
    (let [user (user-signup datasource all-params)]
      (hooked/call ::signup-handler.signup-success (assoc req :user user))
      (auth-success-response user))))

;;---

(defmethod de/template-build-opts ::create-reset-password-token
  [{{:keys [user-email]} :data}]
  {:to user-email
   :text-template "Your reset for {{user-email}}: {{token}} {{uri}}"})

(defn create-reset-password-token-handler
  [{{:keys [datasource send-email frontend-router]} :dependencies
    :keys [all-params]
    :as req}]
  (let [user (user-by-email* datasource (:user/email all-params))]
    (when user
      (let [token      (create-reset-password-token datasource user)
            user-email (:user/email user)
            uri        (:path (r/match-by-name frontend-router
                                               :donut.frontend.identity/reset-password
                                               {:user/password_reset_token token}))]
        (send-email ::create-reset-password-token
                    {:data {:user-email user-email
                            :token      token
                            :uri        uri}})
        (hooked/call ::create-reset-password-token-handler.email-sent
                     (assoc req :email-data {}))))
    {:status 200}))

;;---

(defn login-handler
  [{{:keys [datasource]} :dependencies
    :keys [all-params]}]
  (let [user (user-by-credentials datasource all-params)]
    (if user
      (auth-success-response user)
      {:status  401
       :body    [[:errors {:form ["Could not log you in with that email and password"]}]]
       :session {:identity nil}})))

(defn logout-handler
  [_]
  {:status  200
   :body    [[:auth {:identity nil}]]
   :session {:identity nil}})

(defn check-reset-password-token-handler
  [{{:keys [datasource token-max-age]} :dependencies
    :keys [all-params]}]
  (if (valid-token? datasource
                    (:user/password_reset_token all-params)
                    (or token-max-age DEFAULT-TOKEN-MAX-AGE))
    {:status 200}
    {:status 400}))

(defn reset-password-handler
  [{{:keys [datasource token-max-age]} :dependencies
    :keys                              [all-params]}]
  (or (der/errors-response [:map [:user/password [:string {:min 8}]]]
                           all-params)
      (do
        (reset-password datasource
                        {:token         (:user/password_reset_token all-params)
                         :token-max-age (or token-max-age DEFAULT-TOKEN-MAX-AGE)
                         :user/password (:user/password all-params)})
        {:status 200})))

;;---
;; routes
;;---

(def default-route-opts
  {:group-path "/identity"
   :signup-handler signup-handler
   :login-handler login-handler
   :logout-handler logout-handler
   :check-reset-password-token-handler check-reset-password-token-handler
   :reset-password-handler reset-password-handler
   :create-reset-password-token-handler create-reset-password-token-handler})

(def donut-routes
  [["/signup"
    {:name :donut.endpoint.identity/signup
     :post {:handler (ds/local-ref [:signup-handler])}}]

   ["/login"
    {:name :donut.endpoint.identity/login
     :post {:handler (ds/local-ref [:login-handler])}}]

   ["/logout"
    {:name :donut.endpoint.identity/logout
     :post {:handler (ds/local-ref [:logout-handler])}}]

   ["/reset-password-token/{user/password_reset_token}"
    {:name :donut.endpoint.identity/reset-password-token
     :get  {:handler (ds/local-ref [:check-reset-password-token-handler])}
     :put  {:handler (ds/local-ref [:reset-password-handler])}}]

   ["/reset-password-token"
    {:name :donut.endpoint.identity/create-reset-password-token
     :post {:handler (ds/local-ref [:create-reset-password-token-handler])}}]])

;; TODO schema that checks for donut ref, or the realized type
(def RouteGroupSchema
  [:map
   {:closed true}
   [:group-path {:optional true} :string]
   [:group-opts
    [:map
     [:send-email :any]
     [:datasource :any]
     [:frontend-router :any]]]
   [:signup-handler {:optional true} :any]
   [:login-handler {:optional true} :any]
   [:logout-handler {:optional true} :any]
   [:check-reset-password-token-handler {:optional true} :any]
   [:reset-password-handler {:optional true} :any]
   [:create-reset-password-token-handler {:optional true} :any]])


;; TODO validate datasource satisfies? IdentityStore
(defn identity-route-group
  [& [components]]
  (dsu/validate-with-throw RouteGroupSchema components)
  (-> default-route-opts
      (merge {:routes donut-routes} components)
      (derg/route-group)
      (assoc-in [:route-group ::ds/pre-start-schema]
                [::ds/config
                 [:map
                  [:send-email fn?]
                  [:datasource :any]
                  [:frontend-router :any]]])))
