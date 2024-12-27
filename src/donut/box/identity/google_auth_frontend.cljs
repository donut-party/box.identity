(ns donut.box.identity.google-auth-frontend
  "handlers, subs, components for google auth

  https://developers.google.com/identity/sign-in/web/sign-in
  "
  (:require
   [clojure.walk :as walk]
   [donut.box.identity.frontend :as dbif]
   [donut.frontend.core.utils :as dcu]
   [donut.frontend.nav.flow :as dnf]
   [donut.frontend.sync.flow :as dsf]
   [donut.system :as ds]
   [re-frame.core :as rf]
   [reagent.core :as r]))

(def button-id "donut-google-auth-button")

(defn gis-api
  []
  (dcu/go-get js/window ["google" "accounts" "id"]))

(def google-auth-path [:donut :auth :google-auth])

(rf/reg-fx ::render-button
  (fn [render?]
    (when render?
      (let [render-button (dcu/go-get (gis-api) ["renderButton"])]
        (render-button (dcu/el-by-id button-id) #js{:theme "outline"})))))

;; handle script and button loading async
(rf/reg-event-fx ::google-auth-component-loaded
  [rf/trim-v]
  (fn [{:keys [db]} [component]]
    (let [path   (conj google-auth-path :loaded-components)
          new-db (update-in db path (fnil conj #{}) component)]
      {:db             new-db
       ::render-button (= #{:script :button} (get-in new-db path))})))

(rf/reg-sub :ga-auth-workflow
  (fn [db] (:ga-auth-workflow db)))

(defn goog-auth-callback
  "Called when auth is successful"
  [args]
  (rf/dispatch [::dsf/post
                :donut.endpoint.identity.google-auth/validate-token
                {:params (-> (js->clj args)
                             (walk/keywordize-keys))}]))

(defn goog-auth-initialize
  "Called after the gsi client is loaded, initializes and configures it"
  [config]
  (let [goog-initialize (dcu/go-get (gis-api) ["initialize"])]
    (goog-initialize
     (clj->js {:client_id (:google-signin-client-id config)
               :callback  goog-auth-callback}))
    (rf/dispatch [::google-auth-component-loaded :script])))

(def GoogleAuthComponent
  #::ds{:start (fn [{:keys [::ds/config]}]
                 (js/console.log "loading script")
                 (if (gis-api)
                   (rf/dispatch [::google-auth-component-loaded :script])
                   (dcu/load-script
                    {:url     "https://accounts.google.com/gsi/client"
                     :async   true
                     :on-load (fn [] (goog-auth-initialize config))})))})

;;---
;; init google auth
;;---
;; These functions and handlers:
;; 1. Track the state of whether the auth lib is loaded. Used to determine
;;    whether to attempt to show the signin button.
;; 2. Initialize the google auth lib, giving it the correct config.

(defn ^:export init-google-auth
  "Callback called when GA js lib loads. It eventually lets us know it's safe t
  attempt to render the signin button."
  []
  (prn "exported")
  (rf/dispatch [::init-google-auth]))

;; capture whether or not the gapi lib has loaded so that we can
;; provide feedback to the user on where the auth process is
(rf/reg-cofx ::gapi-signin-state
  (fn [cofx _]
    (assoc cofx :gapi-signin-state (if (and (exists? js/gapi) js/gapi.signin2)
                                     ::initialized
                                     ::uninitialized))))

;; Stores the gapi-lib-state, used in rendering the google auth button.
(rf/reg-event-fx ::init-google-auth
  [(rf/inject-cofx ::gapi-signin-state) rf/trim-v]
  (fn [{:keys [db gapi-signin-state]} _]
    (prn "init google auth" gapi-signin-state)
    (cond-> {:db              (assoc-in db [:ga-auth-workflow :lib-state] gapi-signin-state)
             ::init-ga-signin true}
      (get-in db [:ga-auth-workflow :requires-signout?]) (assoc :dispatch [::ga-signout]))))

(defn init-auth-workflow-state
  [fx]
  (-> fx
      (update-in [:db :ga-auth-workflow :validation-state] #(or % ::unvalidated))
      (update-in [:db :ga-auth-workflow :lib-state] #(or % ::uninitialized))))

;;---
;; GA signin lifecycle
;;---
;; Handles the process after the signin button is clicked and a signin is
;; attempted.

(defn on-signin-fn
  "Handle successful signin with google auth. Called by signin button"
  [success-handler]
  (fn [google-user]
    (rf/dispatch [::ga-button-signin-success
                  {:token (-> ^js google-user
                              .getAuthResponse
                              (dcu/go-get "id_token"))
                   :email (-> ^js google-user
                              .getBasicProfile
                              .getEmail)}
                  success-handler])))

(defn store-ga-response
  [fx user]
  (assoc-in fx [:db :ga-auth-workflow :ga-response] user))

(defn can-validate-ga?
  [{:keys [db]}]
  (let [{:keys [init-state ga-auth-workflow]} db
        {:keys [validation-state lib-state ga-response]} ga-auth-workflow]
    (and (= :init-finished init-state)
         (not= ::validated validation-state)
         (not= ::uninitialized lib-state)
         (empty? (dbif/auth-identity db))
         (not-empty ga-response))))

(defn attempt-ga-server-validation
  [{:keys [db] :as fx} success-handler]
  (if (can-validate-ga? fx)
    (merge {:db (assoc-in db [:ga-auth-workflow :validation-state] ::server-validating)}
           (dsf/sync-req->dispatch
            [:post :session.google-auth-session {:params (get-in db [:ga-auth-workflow :ga-response])
                                                 :on     {:success (or success-handler
                                                                       [[::server-validation-success]
                                                                        [::dnf/dispatch-current]])
                                                          :fail    [::server-validation-failed :$ctx]}}]))
    fx))

;; Called when the user successfully uses the button to sign in. Updates the
;; auth workflow state and includes an effect to dipatch to the server.
(rf/reg-event-fx ::ga-button-signin-success
  [rf/trim-v]
  (fn [cofx [user success-handler]]
    (-> (select-keys cofx [:db])
        (store-ga-response user)
        (attempt-ga-server-validation success-handler))))

(rf/reg-event-fx ::attempt-ga-server-validation
  [rf/trim-v]
  (fn [cofx [success-handler]]
    (attempt-ga-server-validation cofx success-handler)))

(rf/reg-event-fx ::server-validation-success
  [rf/trim-v]
  (fn [{:keys [db]}]
    {:db         (assoc-in db [:ga-auth-workflow :validation-state] ::validated)
     :dispatch-n [[:bcjobs.frontend.handlers/initialize-manage-company-form]
                  [::dnf/dispatch-current]]}))

;; Called when the backend rejects the login token. If the login token
;; is rejected, dispatch the :ga-signout event so that the user is
;; signed out of google signin.
(rf/reg-event-fx ::server-validation-failed
  [rf/trim-v]
  (fn [_ [{:keys [resp]}]]
    {::ga-signout true
     :dispatch    [::update-server-validation-failed-state resp]}))

(rf/reg-event-db ::update-server-validation-failed-state
  [rf/trim-v]
  (fn [db [resp]]
    (update db :ga-auth-workflow merge
            {:validation-state ::unvalidated
             :errors           (-> resp :response-data first second :authorization)})))

;;---
;; logout
;;---

(rf/reg-event-fx ::attempt-ga-signout
  [rf/trim-v]
  (fn [{:keys [db]}]
    (if (= ::initialized (get-in db [:ga-auth-workflow :lib-state]))
      {::ga-signout true}
      {:db (-> db
               (assoc-in [:ga-auth-workflow :requires-signout?] true)
               (dissoc :current-user))})))


;; Signout event. Has to:
;; 1. clear the user data stored in app db
;; 2. call the ga-signout effect to make sure the user is signed out of google signin
(rf/reg-event-fx ::ga-signout
  [rf/trim-v]
  (fn [{:keys [db]}]
    {:db          (assoc db :current-user nil)
     ::ga-signout true}))

;; Effct that clears whatever user was logged in using google signin.
(rf/reg-fx ::ga-signout
  (fn [_]
    (let [gapi          (dcu/go-get js/window ["gapi"])
          auth2         (and gapi (dcu/go-get gapi ["auth2"]))
          auth-instance (and auth2 ((dcu/go-get auth2 ["getAuthInstance"])))
          current-user  (and auth-instance (dcu/go-get auth-instance ["currentUser"]))
          user          (and current-user (.get ^js current-user))]
      (when (and user (.isSignedIn ^js user))
        (.signOut ^js auth-instance)))))


;;---
;; components
;;---

(defn signin-button
  "Google signin button."
  []
  (r/create-class
   {:reagent-render
    (fn [] [:div {:id button-id} "button"])

    :component-did-mount
    (fn [_] (rf/dispatch [::google-auth-component-loaded :button]))}))

(defn logout-button
  []
  (let [{:keys [:user/email]} @(rf/subscribe [:donut.box.identity.frontend/auth-identity])]
    [:div.ga-button
     [:div "Signed in as " email
      [:a.text-white.ml1 {:href     "#"
                          :on-click #(rf/dispatch [:logout])}
       "Sign out"]]]))

(defn login-button
  []
  (let [{:keys [state errors]} @(rf/subscribe [:ga-auth-workflow])]
    [:div.ga-button
     (when errors [:div.ga-error errors])
     (condp = state
       nil                 ""
       ::uninitialized     ""
       ::fetching-session  "Fetching session..."
       ::initialized       [signin-button]
       ::server-validating "Validating login..."
       ::login-failed      [signin-button]
       ::logged-in         [logout-button]
       ::logging-out       "Logging out...")]))

(defn create-account-button
  [& [success-event]]
  (let [{:keys [validation-state lib-state errors]} @(rf/subscribe [:ga-auth-workflow])
        current-user                                @(rf/subscribe [:donut.box.identity.frontend/auth-identity])
        success-event                               (or success-event [:steps/step-1-complete])]
    (if current-user
      [logout-button]
      (when (= lib-state ::initialized)
        [:div.ga-button
         (when errors [:div.ga-error errors])
         (condp = validation-state
           nil                 ""
           ::unvalidated       [signin-button success-event]
           ::validated         [logout-button]
           ::server-validating "Validating login..."
           ::login-failed      [signin-button success-event]
           ::logging-out       "Logging out...")]))))
