(ns donut.identity.identity-store
  (:require
   [buddy.hashers :as buddy-hashers]
   [donut.protocol-template :as dbpt]
   [donut.dbeasy.next-jdbc :as dben]
   [nano-id.core :as nano-id]
   [next.jdbc.sql :as jsql]))

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
  (-user-by-email [datasource email])
  (-user-by-reset-password-token [datasource token])
  (-insert-user! [datasource user])
  (-update-user! [datasource user]))

(dbpt/def-protocol-template
  IdentityStore
  :donut.dbeasy.next-jdbc

  (-user-by-email
   [datasource email]
   (dben/query-one datasource {:select [:*]
                               :from   [:user]
                               :where  [:= :email email]}))

  (-user-by-reset-password-token
   [datasource token]
   (dben/query-one datasource {:select [:*]
                               :from   [:user]
                               :where  [:= :reset_password_token token]}))

  (-insert-user!
   [datasource user]
   (dben/insert! datasource user))

  (-update-user!
   [datasource user]
   (jsql/update! datasource :user user (select-keys user [:user/id]))))

(defn user-by-credentials
  [datasource {:keys [:user/password :user/email]}]
  (let [user (-user-by-email datasource email)]
    (and user
         (not-empty password)
         (:valid (buddy-hashers/verify password (:user/password_hash user)))
         user)))

(defn user-signup!
  [datasource user]
  (-insert-user! datasource (-> user
                                (dissoc :user/password)
                                (assoc :user/password_hash (buddy-hashers/encrypt (:user/password user))))))

(defn create-reset-password-token!
  [datasource user]
  (let [token (nano-id/nano-id 10)]
    (-update-user! datasource
                   {:user/id                              (:user/id user)
                    :user/reset_password_token            token
                    :user/reset_password_token_created_at (current-time-seconds)})
    token))

(defn reset-password!
  [datasource {:keys [token token-max-age :user/password] :as _password-reset}]
  (when-let [user (-user-by-reset-password-token datasource token)]
    (if (token-expired? user token-max-age)
      :expired
      (-update-user! datasource
                     {:user/id                              (:user/id user)
                      :user/password_hash                   (buddy-hashers/encrypt password)
                      :user/password_reset_token            nil
                      :user/password_reset_token_created_at nil}))))

(defn valid-token?
  [datasource token token-max-age]
  (let [user (-user-by-reset-password-token datasource token)]
    (and user (not (token-expired? user token-max-age)))))
