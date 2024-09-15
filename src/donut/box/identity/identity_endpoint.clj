(ns donut.box.identity.identity-endpoint
  (:require
   [donut.box.identity.identity-store :as diis]
   [donut.email :as de]
   [donut.endpoint.response :as der]
   [donut.endpoint.route-group :as derg]
   [donut.hooked :as hooked]
   [donut.sugar.utils :as dsu]
   [donut.system :as ds]
   [reitit.core :as r]))

(defmulti session-identity (fn [user] (:user/type user)))
(defmethod session-identity
  :default
  [user]
  (select-keys user [:user/email]))

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
      (not (diis/-user-by-email datasource email)))]])

(defn signup-handler
  [{{:keys [datasource]} :dependencies
    :keys [all-params]
    :as req}]
  (if-let [response (der/errors-response (UserSignupSchema datasource) all-params)]
    (do
      (hooked/call ::signup-handler.validation-errors (assoc req :errors (:feedback response)))
      response)
    (let [user (diis/user-signup! datasource all-params)]
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
  (let [user (diis/-user-by-email datasource (:user/email all-params))]
    (when user
      (let [token      (diis/create-reset-password-token! datasource user)
            user-email (:user/email user)
            uri        (:path (r/match-by-name frontend-router
                                               :donut.frontend.identity/reset-password
                                               {:user/reset-password-token token}))]
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
  (if-let [user (diis/user-by-credentials datasource all-params)]
    (auth-success-response user)
    {:status  401
     :body    [[:errors {:form ["Could not log you in with that email and password"]}]]
     :session {:identity nil}}))

(defn logout-handler
  [_]
  {:status  200
   :body    [[:auth {:identity nil}]]
   :session {:identity nil}})

(defn check-reset-password-token-handler
  [{{:keys [datasource token-max-age]} :dependencies
    :keys [all-params]}]
  (if (diis/valid-token? datasource
                         (:user/reset-password-token all-params)
                         (or token-max-age diis/DEFAULT-TOKEN-MAX-AGE))
    {:status 200}
    {:status 400}))

(defn reset-password-handler
  [{{:keys [datasource token-max-age]} :dependencies
    :keys                              [all-params]}]
  (or (der/errors-response [:map [:user/password [:string {:min 8}]]]
                           all-params)
      (do
        (diis/reset-password! datasource
                              {:token         (:user/reset-password-token all-params)
                               :token-max-age (or token-max-age diis/DEFAULT-TOKEN-MAX-AGE)
                               :user/password (:user/password all-params)})
        {:status 200})))

;;---
;; routes
;;---

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

   ["/reset-password-token/{user/reset-password-token}"
    {:name :donut.endpoint.identity/reset-password-token
     :get  {:handler (ds/local-ref [:check-reset-password-token-handler])}
     :put  {:handler (ds/local-ref [:reset-password-handler])}}]

   ["/reset-password-token"
    {:name :donut.endpoint.identity/create-reset-password-token
     :post {:handler (ds/local-ref [:create-reset-password-token-handler])}}]])

(def route-group-components
  "Mostly handlers, plus the prefix for the routes"
  {:path-prefix "/identity"
   :routes donut-routes
   :signup-handler signup-handler
   :login-handler login-handler
   :logout-handler logout-handler
   :check-reset-password-token-handler check-reset-password-token-handler
   :reset-password-handler reset-password-handler
   :create-reset-password-token-handler create-reset-password-token-handler})

;; TODO schema that checks for donut ref, or the realized type
(def RouteGroupSchema
  [:map
   {:closed true}
   [:path-prefix {:optional true} :string]
   [:shared-opts
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

(def IdentityRouteGroupSchema
  [::ds/config
   [:map
    [:send-email fn?]
    [:datasource :any]
    [:frontend-router :any]]])

;; TODO validate datasource satisfies? IdentityStore
(defn identity-route-group
  [& [components]]
  (dsu/validate-with-throw RouteGroupSchema components)
  (-> (derg/route-group route-group-components components)
      (assoc-in [:route-group ::ds/pre-start-schema] IdentityRouteGroupSchema)))
