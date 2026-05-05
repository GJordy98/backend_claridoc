-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Hôte : 127.0.0.1
-- Généré le : sam. 25 avr. 2026 à 19:48
-- Version du serveur : 10.4.32-MariaDB
-- Version de PHP : 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Base de données : `claridoc_pro_v2`
--

-- --------------------------------------------------------

--
-- Structure de la table `claridoc_team`
--

CREATE TABLE `claridoc_team` (
  `id` int(11) NOT NULL,
  `nom` varchar(100) NOT NULL,
  `email` varchar(150) NOT NULL,
  `password_hash` varchar(64) NOT NULL,
  `role` enum('SUPERADMIN','SUPPORT','COMMERCIAL') NOT NULL DEFAULT 'SUPPORT',
  `actif` tinyint(1) NOT NULL DEFAULT 1,
  `derniere_connexion` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Déchargement des données de la table `claridoc_team`
--

INSERT INTO `claridoc_team` (`id`, `nom`, `email`, `password_hash`, `role`, `actif`, `derniere_connexion`, `created_at`, `updated_at`) VALUES
(1, 'SuperAdmin ClariDoc', 'admin@claridoc.com', '61e8babebedf3a3719d2dea1320c5e18c326879882cddaa7df444f3b49a01b8c', 'SUPERADMIN', 1, NULL, '2026-04-23 11:42:06', '2026-04-23 11:42:06');

-- --------------------------------------------------------

--
-- Structure de la table `clients`
--

CREATE TABLE `clients` (
  `id` int(11) NOT NULL,
  `holding_id` int(11) DEFAULT NULL,
  `nom` varchar(150) NOT NULL,
  `code_client` varchar(20) NOT NULL,
  `secteur` enum('BANQUE','NOTAIRE','ENTREPRISE') NOT NULL DEFAULT 'ENTREPRISE',
  `email_contact` varchar(150) DEFAULT NULL,
  `telephone` varchar(30) DEFAULT NULL,
  `adresse` text DEFAULT NULL,
  `ville` varchar(100) DEFAULT NULL,
  `pays` varchar(100) NOT NULL DEFAULT 'Cameroun',
  `storage_mode` enum('LOCAL','CLOUD','HYBRID') NOT NULL DEFAULT 'LOCAL',
  `ftp_host` varchar(255) DEFAULT NULL,
  `ftp_port` smallint(6) NOT NULL DEFAULT 21,
  `ftp_user` varchar(100) DEFAULT NULL,
  `ftp_password_enc` varchar(512) DEFAULT NULL,
  `ftp_fingerprint` varchar(255) DEFAULT NULL,
  `ftp_base_path` varchar(255) NOT NULL DEFAULT '/ClariDoc_Cloud/',
  `statut` enum('ACTIF','INACTIF','SUSPENDU') NOT NULL DEFAULT 'ACTIF',
  `created_by` int(11) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Déchargement des données de la table `clients`
--

INSERT INTO `clients` (`id`, `holding_id`, `nom`, `code_client`, `secteur`, `email_contact`, `telephone`, `adresse`, `ville`, `pays`, `storage_mode`, `ftp_host`, `ftp_port`, `ftp_user`, `ftp_password_enc`, `ftp_fingerprint`, `ftp_base_path`, `statut`, `created_by`, `created_at`, `updated_at`) VALUES
(1, 1, 'Banque Atlantique Yaoundé', 'BNK-00001', 'BANQUE', 'it@banque-atlantique-yde.cm', NULL, NULL, 'Yaoundé', 'Cameroun', '', '127.0.0.1', 21, 'claridoc_ftp', 'mPmp2qBgW9I1skdwPefm+w+NAcOn0ekqlcIw98VdBv4=', NULL, '/', 'ACTIF', 1, '2026-04-23 11:42:06', '2026-04-24 10:35:59');

-- --------------------------------------------------------

--
-- Structure de la table `config_encryption`
--

CREATE TABLE `config_encryption` (
  `client_id` int(11) NOT NULL,
  `aes_key_hex` varchar(64) NOT NULL,
  `iv_base_hex` varchar(32) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Déchargement des données de la table `config_encryption`
--

INSERT INTO `config_encryption` (`client_id`, `aes_key_hex`, `iv_base_hex`, `created_at`, `updated_at`) VALUES
(1, 'A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2', 'F1E2D3C4B5A6978869504132F1E2D3C4', '2026-04-23 11:42:06', '2026-04-23 11:42:06');

-- --------------------------------------------------------

--
-- Structure de la table `equipements`
--

CREATE TABLE `equipements` (
  `id` int(11) NOT NULL,
  `type` enum('CAMERA','SCANNER','AUTRE') NOT NULL,
  `marque` varchar(100) DEFAULT NULL,
  `modele` varchar(100) DEFAULT NULL,
  `numero_serie` varchar(100) NOT NULL,
  `client_id` int(11) DEFAULT NULL,
  `date_pret` date DEFAULT NULL,
  `date_retour_prevue` date DEFAULT NULL,
  `date_retour_effectif` date DEFAULT NULL,
  `statut` enum('EN_STOCK','PRETE','EN_MAINTENANCE','PERDU') NOT NULL DEFAULT 'EN_STOCK',
  `notes` text DEFAULT NULL,
  `enregistre_par` int(11) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Déchargement des données de la table `equipements`
--

INSERT INTO `equipements` (`id`, `type`, `marque`, `modele`, `numero_serie`, `client_id`, `date_pret`, `date_retour_prevue`, `date_retour_effectif`, `statut`, `notes`, `enregistre_par`, `created_at`, `updated_at`) VALUES
(1, 'CAMERA', 'CZUR', 'ET18 Pro', 'CZUR-ET18-TEST-001', 1, '2026-04-23', NULL, NULL, 'PRETE', NULL, 1, '2026-04-23 11:42:06', '2026-04-23 11:42:06');

-- --------------------------------------------------------

--
-- Structure de la table `fichiers`
--

CREATE TABLE `fichiers` (
  `id` int(11) NOT NULL,
  `client_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `machine_id` int(11) DEFAULT NULL,
  `nom_fichier` varchar(255) NOT NULL,
  `type_fichier` varchar(10) NOT NULL,
  `taille_octets` bigint(20) DEFAULT NULL,
  `chemin_ftp` text DEFAULT NULL,
  `dossier_logique` varchar(500) DEFAULT NULL,
  `statut_upload` enum('EN_ATTENTE','VALIDE','ECHEC') NOT NULL DEFAULT 'EN_ATTENTE',
  `tentatives_upload` tinyint(4) NOT NULL DEFAULT 0,
  `date_upload` datetime DEFAULT NULL,
  `hash_fichier` varchar(64) DEFAULT NULL,
  `notes` text DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Déchargement des données de la table `fichiers`
--

INSERT INTO `fichiers` (`id`, `client_id`, `user_id`, `machine_id`, `nom_fichier`, `type_fichier`, `taille_octets`, `chemin_ftp`, `dossier_logique`, `statut_upload`, `tentatives_upload`, `date_upload`, `hash_fichier`, `notes`, `created_at`, `updated_at`) VALUES
(1, 1, 1, NULL, '1.jpg', 'JPG', 593293, NULL, '/BNK-00001/Glenn/Andy', 'ECHEC', 1, NULL, NULL, NULL, '2026-04-24 09:54:46', '2026-04-24 12:58:32'),
(2, 1, 1, NULL, '12.jpg', 'JPG', 877496, NULL, '/BNK-00001/Glenn/Andy', 'ECHEC', 1, NULL, NULL, NULL, '2026-04-24 10:19:27', '2026-04-24 12:58:32'),
(3, 1, 1, NULL, '1.jpg', 'JPG', 744382, NULL, '/BNK-00001/BNK-00001/BNK-00001/Glenn/Andy', 'ECHEC', 1, NULL, NULL, NULL, '2026-04-24 10:45:38', '2026-04-24 12:58:32'),
(4, 1, 1, NULL, '124.jpg', 'JPG', 730472, NULL, '/BNK-00001/Glenn/Andy', 'ECHEC', 1, NULL, NULL, NULL, '2026-04-24 11:00:38', '2026-04-24 12:58:32'),
(5, 1, 1, NULL, '123.jpg', 'JPG', 649548, '/BNK-00001/Glenn/123.jpg', '/BNK-00001/Glenn', 'VALIDE', 1, '2026-04-24 11:12:40', NULL, NULL, '2026-04-24 11:12:40', '2026-04-24 11:12:40'),
(6, 1, 1, NULL, '12.pdf', 'PDF', 589868, '/BNK-00001/Glenn/Andy/12.pdf', '/BNK-00001/Glenn/Andy', 'VALIDE', 1, '2026-04-24 11:14:54', NULL, NULL, '2026-04-24 11:14:54', '2026-04-24 11:14:54'),
(7, 1, 1, NULL, '12.jpg', 'JPG', 572179, '/BNK-00001/Glenn/Andy/12.jpg', '/BNK-00001/Glenn/Andy', 'VALIDE', 1, '2026-04-24 11:16:07', NULL, NULL, '2026-04-24 11:16:07', '2026-04-24 11:16:07'),
(8, 1, 1, NULL, '1245.jpg', 'JPG', 866313, '/BNK-00001/Glenn/1245.jpg', '/BNK-00001/Glenn', 'VALIDE', 1, '2026-04-24 12:01:33', NULL, NULL, '2026-04-24 12:01:33', '2026-04-24 12:01:33');

-- --------------------------------------------------------

--
-- Structure de la table `holdings`
--

CREATE TABLE `holdings` (
  `id` int(11) NOT NULL,
  `nom` varchar(150) NOT NULL,
  `code_holding` varchar(20) NOT NULL,
  `email_contact` varchar(150) DEFAULT NULL,
  `telephone` varchar(30) DEFAULT NULL,
  `actif` tinyint(1) NOT NULL DEFAULT 1,
  `created_by` int(11) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Déchargement des données de la table `holdings`
--

INSERT INTO `holdings` (`id`, `nom`, `code_holding`, `email_contact`, `telephone`, `actif`, `created_by`, `created_at`, `updated_at`) VALUES
(1, 'Groupe Atlantique Cameroun', 'HLD-00001', 'direction@atlantique.cm', NULL, 1, 1, '2026-04-23 11:42:06', '2026-04-23 11:42:06');

-- --------------------------------------------------------

--
-- Structure de la table `licences`
--

CREATE TABLE `licences` (
  `id` int(11) NOT NULL,
  `client_id` int(11) NOT NULL,
  `code_licence` varchar(50) NOT NULL,
  `palier` enum('STARTER','BUSINESS','PRO','ENTERPRISE') NOT NULL DEFAULT 'STARTER',
  `max_utilisateurs` tinyint(4) NOT NULL DEFAULT 5,
  `max_machines` tinyint(4) NOT NULL DEFAULT 3,
  `max_equipements` tinyint(4) NOT NULL DEFAULT 1,
  `utilisateurs_actifs` tinyint(4) NOT NULL DEFAULT 0,
  `machines_actives` tinyint(4) NOT NULL DEFAULT 0,
  `equipements_actifs` tinyint(4) NOT NULL DEFAULT 0,
  `date_debut` date NOT NULL,
  `date_fin` date NOT NULL,
  `renouvellement_auto` tinyint(1) NOT NULL DEFAULT 0,
  `statut` enum('ACTIVE','EXPIREE','SUSPENDUE') NOT NULL DEFAULT 'ACTIVE',
  `notes` text DEFAULT NULL,
  `cree_par` int(11) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Déchargement des données de la table `licences`
--

INSERT INTO `licences` (`id`, `client_id`, `code_licence`, `palier`, `max_utilisateurs`, `max_machines`, `max_equipements`, `utilisateurs_actifs`, `machines_actives`, `equipements_actifs`, `date_debut`, `date_fin`, `renouvellement_auto`, `statut`, `notes`, `cree_par`, `created_at`, `updated_at`) VALUES
(1, 1, 'CDL-2025-BNK-00001', 'STARTER', 5, 3, 1, 3, 1, 0, '2026-04-23', '2027-04-23', 0, 'ACTIVE', NULL, 1, '2026-04-23 11:42:06', '2026-04-23 12:00:07');

-- --------------------------------------------------------

--
-- Structure de la table `licence_activations`
--

CREATE TABLE `licence_activations` (
  `id` int(11) NOT NULL,
  `licence_id` int(11) NOT NULL,
  `machine_id` int(11) DEFAULT NULL,
  `equipement_id` int(11) DEFAULT NULL,
  `action` enum('ACTIVATION','REVOCATION','SUSPENSION','RENOUVELLEMENT','CHANGEMENT_PALIER') NOT NULL,
  `effectue_par` int(11) DEFAULT NULL,
  `date_action` datetime NOT NULL DEFAULT current_timestamp(),
  `details` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Structure de la table `logs`
--

CREATE TABLE `logs` (
  `id` bigint(20) NOT NULL,
  `client_id` int(11) DEFAULT NULL,
  `user_id` int(11) DEFAULT NULL,
  `machine_id` int(11) DEFAULT NULL,
  `team_id` int(11) DEFAULT NULL,
  `action` varchar(100) NOT NULL,
  `entite` varchar(50) DEFAULT NULL,
  `entite_id` int(11) DEFAULT NULL,
  `details` text DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `resultat` enum('SUCCES','ECHEC','AVERTISSEMENT') NOT NULL DEFAULT 'SUCCES',
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Structure de la table `machines_autorisees`
--

CREATE TABLE `machines_autorisees` (
  `id` int(11) NOT NULL,
  `client_id` int(11) NOT NULL,
  `hardware_id` varchar(64) NOT NULL,
  `nom_machine` varchar(100) DEFAULT NULL,
  `os_version` varchar(100) DEFAULT NULL,
  `version_claridoc` varchar(20) DEFAULT NULL,
  `premiere_connexion` datetime NOT NULL DEFAULT current_timestamp(),
  `derniere_connexion` datetime DEFAULT NULL,
  `statut` enum('ACTIVE','REVOQUEE','SUSPENDUE') NOT NULL DEFAULT 'ACTIVE',
  `autorisee_par` int(11) DEFAULT NULL,
  `notes` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Déchargement des données de la table `machines_autorisees`
--

INSERT INTO `machines_autorisees` (`id`, `client_id`, `hardware_id`, `nom_machine`, `os_version`, `version_claridoc`, `premiere_connexion`, `derniere_connexion`, `statut`, `autorisee_par`, `notes`) VALUES
(1, 1, 'c11f4c2a9bc6f621d6bbd355851b6f49', 'PC-DEV-GLENN', NULL, NULL, '2026-04-23 12:00:07', '2026-04-24 11:53:12', 'ACTIVE', 1, NULL);

--
-- Déclencheurs `machines_autorisees`
--
DELIMITER $$
CREATE TRIGGER `trg_machine_insert` AFTER INSERT ON `machines_autorisees` FOR EACH ROW BEGIN
    IF NEW.statut = 'ACTIVE' THEN
        UPDATE licences
        SET machines_actives = machines_actives + 1
        WHERE client_id = NEW.client_id;
    END IF;
END
$$
DELIMITER ;
DELIMITER $$
CREATE TRIGGER `trg_machine_update` AFTER UPDATE ON `machines_autorisees` FOR EACH ROW BEGIN
    IF OLD.statut != 'ACTIVE' AND NEW.statut = 'ACTIVE' THEN
        UPDATE licences SET machines_actives = machines_actives + 1 WHERE client_id = NEW.client_id;
    END IF;
    IF OLD.statut = 'ACTIVE' AND NEW.statut != 'ACTIVE' THEN
        UPDATE licences SET machines_actives = GREATEST(0, machines_actives - 1) WHERE client_id = NEW.client_id;
    END IF;
END
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Structure de la table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `client_id` int(11) NOT NULL,
  `role` enum('CHEF','ADMIN','USER') NOT NULL DEFAULT 'USER',
  `nom` varchar(100) NOT NULL,
  `prenom` varchar(100) NOT NULL,
  `email` varchar(150) NOT NULL,
  `password_hash` varchar(64) NOT NULL,
  `actif` tinyint(1) NOT NULL DEFAULT 1,
  `premiere_connexion` datetime DEFAULT NULL,
  `derniere_connexion` datetime DEFAULT NULL,
  `cree_par` int(11) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Déchargement des données de la table `users`
--

INSERT INTO `users` (`id`, `client_id`, `role`, `nom`, `prenom`, `email`, `password_hash`, `actif`, `premiere_connexion`, `derniere_connexion`, `cree_par`, `created_at`, `updated_at`) VALUES
(1, 1, 'CHEF', 'Nkoulou', 'Emmanuel', 'chef@banque-atlantique-yde.cm', 'c04432633f574c3cb6cbdd53ec9f77f8bbdceb948db233d323630ae0937fde04', 1, NULL, '2026-04-24 11:56:49', NULL, '2026-04-23 11:42:06', '2026-04-24 11:56:49'),
(2, 1, 'ADMIN', 'Mbarga', 'Sylvie', 'admin@banque-atlantique-yde.cm', '188209e1a05f534cbbabe055a14ea1b7b1d940033a7647483b04f18d58c0a87a', 1, NULL, NULL, 1, '2026-04-23 11:42:06', '2026-04-23 11:42:06'),
(3, 1, 'USER', 'Essama', 'Marie', 'marie.essama@banque-atlantique-yde.cm', '6bee981513381ca3afe7bfb9ec8e9d92065518eb599925d4ede92c7202b9892e', 1, NULL, NULL, 2, '2026-04-23 11:42:06', '2026-04-23 11:42:06');

--
-- Déclencheurs `users`
--
DELIMITER $$
CREATE TRIGGER `trg_user_actif_delete` AFTER DELETE ON `users` FOR EACH ROW BEGIN
    IF OLD.actif = TRUE THEN
        UPDATE licences
        SET utilisateurs_actifs = GREATEST(0, utilisateurs_actifs - 1)
        WHERE client_id = OLD.client_id;
    END IF;
END
$$
DELIMITER ;
DELIMITER $$
CREATE TRIGGER `trg_user_actif_insert` AFTER INSERT ON `users` FOR EACH ROW BEGIN
    IF NEW.actif = TRUE THEN
        UPDATE licences
        SET utilisateurs_actifs = utilisateurs_actifs + 1
        WHERE client_id = NEW.client_id;
    END IF;
END
$$
DELIMITER ;
DELIMITER $$
CREATE TRIGGER `trg_user_actif_update` AFTER UPDATE ON `users` FOR EACH ROW BEGIN
    -- User activé
    IF OLD.actif = FALSE AND NEW.actif = TRUE THEN
        UPDATE licences
        SET utilisateurs_actifs = utilisateurs_actifs + 1
        WHERE client_id = NEW.client_id;
    END IF;
    -- User désactivé
    IF OLD.actif = TRUE AND NEW.actif = FALSE THEN
        UPDATE licences
        SET utilisateurs_actifs = GREATEST(0, utilisateurs_actifs - 1)
        WHERE client_id = NEW.client_id;
    END IF;
END
$$
DELIMITER ;

--
-- Index pour les tables déchargées
--

--
-- Index pour la table `claridoc_team`
--
ALTER TABLE `claridoc_team`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `email` (`email`);

--
-- Index pour la table `clients`
--
ALTER TABLE `clients`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `code_client` (`code_client`);

--
-- Index pour la table `config_encryption`
--
ALTER TABLE `config_encryption`
  ADD PRIMARY KEY (`client_id`);

--
-- Index pour la table `equipements`
--
ALTER TABLE `equipements`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `numero_serie` (`numero_serie`);

--
-- Index pour la table `fichiers`
--
ALTER TABLE `fichiers`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_client_statut` (`client_id`,`statut_upload`),
  ADD KEY `idx_client_dossier` (`client_id`,`dossier_logique`(100));

--
-- Index pour la table `holdings`
--
ALTER TABLE `holdings`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `code_holding` (`code_holding`);

--
-- Index pour la table `licences`
--
ALTER TABLE `licences`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `client_id` (`client_id`),
  ADD UNIQUE KEY `code_licence` (`code_licence`);

--
-- Index pour la table `licence_activations`
--
ALTER TABLE `licence_activations`
  ADD PRIMARY KEY (`id`);

--
-- Index pour la table `logs`
--
ALTER TABLE `logs`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_client_date` (`client_id`,`created_at`),
  ADD KEY `idx_action` (`action`),
  ADD KEY `idx_user_date` (`user_id`,`created_at`);

--
-- Index pour la table `machines_autorisees`
--
ALTER TABLE `machines_autorisees`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_client_hardware` (`client_id`,`hardware_id`);

--
-- Index pour la table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_email_client` (`email`,`client_id`);

--
-- AUTO_INCREMENT pour les tables déchargées
--

--
-- AUTO_INCREMENT pour la table `claridoc_team`
--
ALTER TABLE `claridoc_team`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT pour la table `clients`
--
ALTER TABLE `clients`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT pour la table `equipements`
--
ALTER TABLE `equipements`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT pour la table `fichiers`
--
ALTER TABLE `fichiers`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;

--
-- AUTO_INCREMENT pour la table `holdings`
--
ALTER TABLE `holdings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT pour la table `licences`
--
ALTER TABLE `licences`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT pour la table `licence_activations`
--
ALTER TABLE `licence_activations`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pour la table `logs`
--
ALTER TABLE `logs`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pour la table `machines_autorisees`
--
ALTER TABLE `machines_autorisees`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT pour la table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
