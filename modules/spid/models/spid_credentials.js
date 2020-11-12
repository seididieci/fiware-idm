// BD to store all eidas credentials of an application

module.exports = function (sequelize, DataTypes) {
  const SPIDCredentials = sequelize.define(
    'SPIDCredentials',
    {
      id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true
      },
      // entity_id: {
      //   type:
      //     DataTypes.STRING(255) +
      //     (sequelize.getDialect() === 'mysql' ? ' CHARSET utf8mb4 COLLATE utf8mb4_unicode_ci' : ''),
      //   validate: { notEmpty: { msg: 'entity_id' } }
      // },
      // assert_endpoint: {
      //   type:
      //     DataTypes.STRING(255) +
      //     (sequelize.getDialect() === 'mysql' ? ' CHARSET utf8mb4 COLLATE utf8mb4_unicode_ci' : ''),
      //   validate: { notEmpty: { msg: 'assert_endpoint' } }
      // },
      auth_context: {
        type:
          DataTypes.STRING(255) +
          (sequelize.getDialect() === 'mysql' ? ' CHARSET utf8mb4 COLLATE utf8mb4_unicode_ci' : ''),
        validate: { notEmpty: { msg: 'auth_context' } }
      },
      organization_name: {
        type:
          DataTypes.STRING(255) +
          (sequelize.getDialect() === 'mysql' ? ' CHARSET utf8mb4 COLLATE utf8mb4_unicode_ci' : ''),
        validate: {
          notEmpty: { msg: 'organization_name' }
        }
      },
      organization_display_name: {
        type:
          DataTypes.STRING(255) +
          (sequelize.getDialect() === 'mysql' ? ' CHARSET utf8mb4 COLLATE utf8mb4_unicode_ci' : ''),
        validate: { notEmpty: { msg: 'organization_display_name' } }
      },
      organization_url: {
        type:
          DataTypes.STRING(255) +
          (sequelize.getDialect() === 'mysql' ? ' CHARSET utf8mb4 COLLATE utf8mb4_unicode_ci' : ''),
        validate: { notEmpty: { msg: 'organization_url' } }
      },
      attributes_list: {
        type: DataTypes.JSON(),
        get() {
          const default_json = {
            name: 'Required attributes',
            values: ['fiscalNumber', 'name', 'familyName', 'email']
          };
          const attributes_list_keys = this.getDataValue('attributes_list')
            ? Object.keys(this.getDataValue('attributes_list')).length
            : 0;
          return attributes_list_keys > 0 ? this.getDataValue('attributes_list') : default_json;
        }
      }
    },
    {
      tableName: 'spid_credentials',
      timestamps: false,
      underscored: true
    }
  );

  return SPIDCredentials;
};
