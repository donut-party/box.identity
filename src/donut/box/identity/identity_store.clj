(ns donut.box.identity.identity-store
  (:require
   [buddy.hashers :as buddy-hashers]
   [donut.protocol-implementation :as dpi]
   [nano-id.core :as nano-id]
   [next.jdbc.sql :as jsql]))

(def DEFAULT-TOKEN-MAX-AGE
  "twenty minutes"
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
        (:user/password-reset-token-created-at user))
     token-max-age))

;;---
;; data store interactions
;;---

(defprotocol IdentityStore
  (-user-by-email [datasource email])
  (-user-by-reset-password-token [datasource token])
  (-insert-user! [datasource user])
  (-update-user! [datasource user]))

#_{:clj-kondo/ignore [:unresolved-namespace]}
(dpi/def-protocol-implementation
  IdentityStore
  ::dbeasy.next-jdbc

  (-user-by-email
   [datasource email]
   (donut.dbeasy.next-jdbc/query-one datasource {:select [:*]
                                                 :from   [:user]
                                                 :where  [:= :email email]}))

  (-user-by-reset-password-token
   [datasource token]
   (donut.dbeasy.next-jdbc/query-one datasource {:select [:*]
                                                 :from   [:user]
                                                 :where  [:= :reset-password-token token]}))

  (-insert-user!
   [datasource user]
   (donut.dbeasy.next-jdbc/insert! datasource user))

  (-update-user!
   [datasource user]
   (jsql/update! datasource :user user (select-keys user [:user/id]))))

#_{:clj-kondo/ignore [:unresolved-namespace]}
(dpi/def-protocol-implementation
  IdentityStore
  ::datomic-client
  
  (-user-by-email
   [conn email]
   (->> (datomic.client.api/q '[:find (pull ?e [:*])
                                :in $ ?email
                                :where [?e :user/email ?email]]
                              (datomic.client.api/db conn)
                              email)
        ffirst))

  (-user-by-reset-password-token
   [conn token]
   (->> (datomic.client.api/q '[:find (pull ?e [:*])
                                :in $ ?token
                                :where [?e :user/password-reset-token ?token]]
                              (datomic.client.api/db conn)
                              token)
        ffirst))

  (-insert-user!
   [conn user]
   (datomic.client.api/transact conn {:tx-data [(select-keys user [:user/email :user/name])]})
   (-user-by-email conn (:user/email user)))

  (-update-user!
   [conn user]
   (datomic.client.api/transact conn {:tx-data [(assoc user :db/id [:user/email (:user/email user)])]})
   user))

(defn user-by-credentials
  [datasource {:keys [:user/password :user/email]}]
  (when-let [user (-user-by-email datasource email)]
    (prn "user" user)
    (and
     (not-empty password)
     (:valid (buddy-hashers/verify password (:user/password-hash user)))
     user)))

(defn user-signup!
  [datasource user]
  (-insert-user! datasource (-> user
                                (dissoc :user/password)
                                (assoc :user/password-hash (buddy-hashers/encrypt (:user/password user))))))

(defn create-reset-password-token!
  [datasource user]
  (let [token (nano-id/nano-id 10)]
    (-update-user! datasource
                   {:user/id                              (:user/id user)
                    :user/reset-password-token            token
                    :user/reset-password-token_created_at (current-time-seconds)})
    token))

(defn reset-password!
  [datasource {:keys [token token-max-age :user/password] :as _password-reset}]
  (when-let [user (-user-by-reset-password-token datasource token)]
    (if (token-expired? user token-max-age)
      :expired
      (-update-user! datasource
                     {:user/id                              (:user/id user)
                      :user/password-hash                   (buddy-hashers/encrypt password)
                      :user/password-reset-token            nil
                      :user/password-reset-token-created-at nil}))))

(defn valid-token?
  [datasource token token-max-age]
  (let [user (-user-by-reset-password-token datasource token)]
    (and user (not (token-expired? user token-max-age)))))
