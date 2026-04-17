(ns donut.box.identity.google-auth-frontend
  "handlers, subs, components for google auth
  https://developers.google.com/identity/gsi/web/reference/js-reference
  "
  (:require
   [clojure.walk :as walk]
   [donut.frontend.core.utils :as dcu]
   [donut.frontend.events :as dfe]
   [donut.frontend.nav.flow :as dnf]
   [donut.frontend.sync.flow :as dsf]
   [donut.system :as ds]
   [re-frame.core :as rf]
   [reagent.core :as r]))

(def button-id "donut-google-auth-button")

(defn gis-api
  []
  (dcu/go-get js/window ["google" "accounts" "id"]))

(def google-auth-path
  [:donut :auth-workflow :google-auth])
(def validate-token-failed?-path
  (conj google-auth-path :validate-token-failed?))
(def loaded-components-path
  (conj google-auth-path :loaded-components))

(rf/reg-event-db ::validate-token-failed
  [rf/trim-v]
  (fn [db]
    (assoc-in db validate-token-failed?-path true)))

(rf/reg-sub ::validate-token-failed?
  (fn [db]
    (get-in db validate-token-failed?-path)))

;; when the button is ready to be rendered (placeholder is in dom, library has
;; loaded) then render it
(rf/reg-fx ::render-google-auth-button
  (fn [render?]
    (when render?
      (let [render-button (dcu/go-get (gis-api) ["renderButton"])]
        (render-button (dcu/el-by-id button-id) #js{:theme "outline"})))))

;; handle script and button loading async
(rf/reg-event-fx ::google-auth-component-loaded
  [rf/trim-v]
  (fn [{:keys [db]} [component]]
    (let [new-db (update-in db loaded-components-path (fnil conj #{}) component)]
      (cond-> {:db new-db}
        (= #{:script :button} (get-in new-db loaded-components-path)) (assoc ::render-google-auth-button true)))))

(rf/reg-sub :ga-auth-workflow
  (fn [db] (:ga-auth-workflow db)))

;;---
;; UI components
;;---

(defn signin-button-reactive
  [opts]
  (r/create-class
   {:reagent-render
    (fn [] [:div (merge {:id button-id} opts)])
    :component-did-mount
    (fn [_] (rf/dispatch [::google-auth-component-loaded :button]))}))

(defn signin-fail-message
  []
  (when @(rf/subscribe [::validate-token-failed?])
    [:div "There was a problem signing in. Please try again."]))

(defn signin-button
  "Google signin button."
  [opts]
  [:div
   [signin-fail-message]
   [signin-button-reactive opts]])

;;---
;; system components
;;---

(defn dispatch-validate-token
  "Called when user authenticates with google"
  [google-auth-token dispatch-opts]
  (rf/dispatch [::dsf/post
                {::dsf/req (merge {:route-name :donut.endpoint.identity.google-auth/validate-token
                                   :params     (-> google-auth-token js->clj walk/keywordize-keys)}
                                  dispatch-opts)
                 ::dfe/on  {:success [[::dnf/navigate-route {:route-name :home}]]
                            :fail    [[::validate-token-failed]]}}]))

(defn google-auth-initialize
  "Called after the gsi client is loaded; initializes and configures it"
  [config]
  (let [goog-initialize (dcu/go-get (gis-api) ["initialize"])]
    (goog-initialize
     (clj->js {:client_id (:google-signin-client-id config)
               :callback  #(dispatch-validate-token % (:validate-token-dispatch-opts config))}))

    ;; TODO logic for one-tap prompt
    #_((dcu/go-get (gis-api) ["prompt"]))
    (rf/dispatch [::google-auth-component-loaded :script])))

(def GoogleAuthComponent
  #::ds{:start (fn [{:keys [::ds/config]}]
                 (if (gis-api)
                   (rf/dispatch [::google-auth-component-loaded :script])
                   (dcu/load-script
                    {:url     "https://accounts.google.com/gsi/client"
                     :async   true
                     :on-load (fn [] (google-auth-initialize config))})))})
