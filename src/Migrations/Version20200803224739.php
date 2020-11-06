<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20200803224739 extends AbstractMigration
{
    public function getDescription() : string
    {
        return '';
    }

    public function up(Schema $schema) : void
    {
        // this up() migration is auto-generated, please modify it to your needs
        $this->addSql('CREATE TABLE content_item (id INT AUTO_INCREMENT NOT NULL, course_id INT NOT NULL, content_type VARCHAR(255) NOT NULL, lms_content_id VARCHAR(512) NOT NULL, updated DATETIME NOT NULL, metadata LONGTEXT DEFAULT NULL, active TINYINT(1) NOT NULL, title VARCHAR(255) NOT NULL, INDEX IDX_D279C8DB591CC992 (course_id), PRIMARY KEY(id)) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB');
        $this->addSql('CREATE TABLE course (id INT AUTO_INCREMENT NOT NULL, institution_id INT NOT NULL, title VARCHAR(255) NOT NULL, lms_account_id VARCHAR(255) DEFAULT NULL, lms_course_id VARCHAR(255) DEFAULT NULL, last_updated DATETIME DEFAULT NULL, active TINYINT(1) DEFAULT NULL, dirty TINYINT(1) DEFAULT NULL, INDEX IDX_169E6FB910405986 (institution_id), PRIMARY KEY(id)) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB');
        $this->addSql('CREATE TABLE institution (id INT AUTO_INCREMENT NOT NULL, title VARCHAR(255) NOT NULL, lms_domain VARCHAR(255) DEFAULT NULL, lms_id VARCHAR(64) DEFAULT NULL, lms_account_id VARCHAR(255) DEFAULT NULL, consumer_key VARCHAR(255) DEFAULT NULL, shared_secret VARCHAR(255) DEFAULT NULL, developer_id VARCHAR(255) DEFAULT NULL, developer_key VARCHAR(255) DEFAULT NULL, created DATETIME NOT NULL, status TINYINT(1) NOT NULL, vanity_url VARCHAR(255) DEFAULT NULL, metadata LONGTEXT DEFAULT NULL, api_client_id VARCHAR(255) DEFAULT NULL, api_client_secret VARCHAR(255) DEFAULT NULL, PRIMARY KEY(id)) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB');
        $this->addSql('CREATE TABLE issue (id INT AUTO_INCREMENT NOT NULL, content_item_id INT NOT NULL, scan_rule_id VARCHAR(255) NOT NULL, html LONGTEXT DEFAULT NULL, type VARCHAR(255) NOT NULL, status TINYINT(1) NOT NULL, INDEX IDX_12AD233ECD678BED (content_item_id), PRIMARY KEY(id)) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB');
        $this->addSql('CREATE TABLE issue_report (issue_id INT NOT NULL, report_id INT NOT NULL, INDEX IDX_36DFFDA35E7AA58C (issue_id), INDEX IDX_36DFFDA34BD2A4C0 (report_id), PRIMARY KEY(issue_id, report_id)) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB');
        $this->addSql('CREATE TABLE log_entry (id INT AUTO_INCREMENT NOT NULL, user_id INT DEFAULT NULL, course_id INT DEFAULT NULL, message LONGTEXT DEFAULT NULL, severity VARCHAR(255) NOT NULL, created DATETIME NOT NULL, INDEX IDX_B5F762DA76ED395 (user_id), INDEX IDX_B5F762D591CC992 (course_id), PRIMARY KEY(id)) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB');
        $this->addSql('CREATE TABLE report (id INT AUTO_INCREMENT NOT NULL, course_id INT NOT NULL, data LONGTEXT DEFAULT NULL, created DATETIME NOT NULL, errors INT DEFAULT NULL, suggestions INT DEFAULT NULL, ready TINYINT(1) NOT NULL, INDEX IDX_C42F7784591CC992 (course_id), PRIMARY KEY(id)) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB');
        $this->addSql('CREATE TABLE user (id INT AUTO_INCREMENT NOT NULL, institution_id INT NOT NULL, username VARCHAR(180) NOT NULL, roles JSON DEFAULT NULL, lms_user_id VARCHAR(128) NOT NULL, api_key VARCHAR(255) DEFAULT NULL, refresh_token VARCHAR(255) DEFAULT NULL, created DATETIME NOT NULL, last_login DATETIME NOT NULL, UNIQUE INDEX UNIQ_8D93D649F85E0677 (username), INDEX IDX_8D93D64910405986 (institution_id), PRIMARY KEY(id)) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB');
        $this->addSql('ALTER TABLE content_item ADD CONSTRAINT FK_D279C8DB591CC992 FOREIGN KEY (course_id) REFERENCES course (id)');
        $this->addSql('ALTER TABLE course ADD CONSTRAINT FK_169E6FB910405986 FOREIGN KEY (institution_id) REFERENCES institution (id)');
        $this->addSql('ALTER TABLE issue ADD CONSTRAINT FK_12AD233ECD678BED FOREIGN KEY (content_item_id) REFERENCES content_item (id)');
        $this->addSql('ALTER TABLE issue_report ADD CONSTRAINT FK_36DFFDA35E7AA58C FOREIGN KEY (issue_id) REFERENCES issue (id) ON DELETE CASCADE');
        $this->addSql('ALTER TABLE issue_report ADD CONSTRAINT FK_36DFFDA34BD2A4C0 FOREIGN KEY (report_id) REFERENCES report (id) ON DELETE CASCADE');
        $this->addSql('ALTER TABLE log_entry ADD CONSTRAINT FK_B5F762DA76ED395 FOREIGN KEY (user_id) REFERENCES user (id)');
        $this->addSql('ALTER TABLE log_entry ADD CONSTRAINT FK_B5F762D591CC992 FOREIGN KEY (course_id) REFERENCES course (id)');
        $this->addSql('ALTER TABLE report ADD CONSTRAINT FK_C42F7784591CC992 FOREIGN KEY (course_id) REFERENCES course (id)');
        $this->addSql('ALTER TABLE user ADD CONSTRAINT FK_8D93D64910405986 FOREIGN KEY (institution_id) REFERENCES institution (id)');
    }

    public function down(Schema $schema) : void
    {
        // this down() migration is auto-generated, please modify it to your needs
        $this->addSql('ALTER TABLE issue DROP FOREIGN KEY FK_12AD233ECD678BED');
        $this->addSql('ALTER TABLE content_item DROP FOREIGN KEY FK_D279C8DB591CC992');
        $this->addSql('ALTER TABLE log_entry DROP FOREIGN KEY FK_B5F762D591CC992');
        $this->addSql('ALTER TABLE report DROP FOREIGN KEY FK_C42F7784591CC992');
        $this->addSql('ALTER TABLE course DROP FOREIGN KEY FK_169E6FB910405986');
        $this->addSql('ALTER TABLE user DROP FOREIGN KEY FK_8D93D64910405986');
        $this->addSql('ALTER TABLE issue_report DROP FOREIGN KEY FK_36DFFDA35E7AA58C');
        $this->addSql('ALTER TABLE issue_report DROP FOREIGN KEY FK_36DFFDA34BD2A4C0');
        $this->addSql('ALTER TABLE log_entry DROP FOREIGN KEY FK_B5F762DA76ED395');
        $this->addSql('DROP TABLE content_item');
        $this->addSql('DROP TABLE course');
        $this->addSql('DROP TABLE institution');
        $this->addSql('DROP TABLE issue');
        $this->addSql('DROP TABLE issue_report');
        $this->addSql('DROP TABLE log_entry');
        $this->addSql('DROP TABLE report');
        $this->addSql('DROP TABLE user');
    }
}