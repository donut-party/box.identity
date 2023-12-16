(ns donut.box.identity.frontend
  (:require
   [donut.frontend.auth.flow :as daf]
   [donut.frontend.core.utils :as dcu]
   [donut.frontend.form.components :as dfc]
   [donut.frontend.form.feedback :as dffk]
   [donut.frontend.form.flow :as dff]
   [donut.frontend.nav.components :as dnc]
   [donut.frontend.nav.flow :as dnf]
   [donut.frontend.routes :as dfr]
   [donut.frontend.sync.flow :as dsf]
   [re-frame.core :as rf]))


(def UserLoginSchema
  [:map
   [:user/email
    [:re {:description "https://github.com/gfredericks/test.chuck/issues/46"
          :gen/fmap '(constantly "random@example.com")
          :error/message "Please enter an email address"}
     #"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}$"]]
   [:user/password  [:string {:min 8}]]])

(def feedback-fn
  (dffk/merge-feedback-fns
   (dffk/malli-error-feedback-fn UserLoginSchema)
   dffk/stored-error-feedback))

(def submit-opts
  {:on {:success [::dff/clear-form :$ctx]
        :fail    [::dff/clear :$ctx [:buffer :input-events]]}})

(defn login-form
  []
  [:div.donut.box.identity.login
   [:h1 "Login"]
   (dfc/with-form [:post :donut.endpoint.identity/login]
     {:donut.form/feedback-fn feedback-fn}
     [:form {:on-submit
             (dcu/prevent-default #(*submit submit-opts))}
      [:div
       [:h3 "Log in"]
       [*field :email :user/email {:required true :placeholder "mary@gmail.com"}]
       [*field :password :user/password {:required true}]
       [:input {:type  "submit"
                :class "primary ready"
                :value "log in"}]
       (when-let [errors (:errors @*form-feedback)]
         (->> errors
              (map (fn [e] [:div.error e]))
              (into [:div.errors])))]])])

(defn forgot-password-form
  []
  [:div.donut.box.identity.forgot-password
   [:h1 "Forgot Password"]
   (dfc/with-form [:post :donut.endpoint.identity/create-reset-password-token]
     {:donut.form/feedback-fn feedback-fn}
     [:form {:on-submit
             (dcu/prevent-default #(*submit submit-opts))}
      [:div
       [*field :email :user/email {:required true :placeholder "mary@gmail.com"}]
       [:input {:type  "submit"
                :class "primary ready"
                :value "send reset email"}]]])])


(defn reset-password-form
  []
  [:div
   [:h1 "Reset Password"]
   (let [invalid? @(rf/subscribe [::daf/reset-password-token-check-failed?])]
     (dfc/with-form [:put :donut.endpoint.identity/reset-password-token]
       {:donut.form/initial-state {:buffer @(rf/subscribe [::dnf/params])}
        :donut.form/feedback-fn feedback-fn}
       [:form {:on-submit
               (dcu/prevent-default #(*submit submit-opts))}
        (when invalid?
          [:div "Your password reset request has expired. "
           [dnc/simple-route-link {:route-name :forgot-password}
            "Please submit a new password reset request."]])
        [:div.create-user-form
         [*field :password :user/password {:required true
                                           :disabled invalid?}]
         [:input {:type  "submit"
                  :class "primary ready"
                  :value "reset password"}]]]))])


(dfr/defroutes routes
  [["/login"
    {:name       :login
     :components {:main [login-form]}}]
   ["/forgot-password"
    {:name       :forgot-password
     :components {:main [forgot-password-form]}}]
   ["/reset-password/{user/reset_password_token}"
    {:name       :reset-password
     :components {:main [reset-password-form]}
     :lifecycle  {:enter (fn [_old-route _new-route params]
                           [[::daf/clear-reset-password-token-check]
                            [::dsf/get
                             :donut.endpoint.identity/reset-password-token
                             {:route-params (:params params)
                              :on           {:fail [::daf/reset-password-token-check-failed]}}]])}}]])
