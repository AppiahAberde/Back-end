const { DataTypes } = require('sequelize');

module.exports = model;

function model(sequelize) {
    const attributes = {
        invoiceID: { type: DataTypes.STRING, allowNull: false},
        orderID: { type: DataTypes.STRING},
        serviceType: { type: DataTypes.STRING, allowNull: false },
        addressReceiver: { type: DataTypes.STRING, allowNull: false },
        amountPaid: { type: DataTypes.STRING, allowNull: false },
        volumeReceived: { type: DataTypes.STRING, allowNull: false },
        fees: { type: DataTypes.STRING, allowNull: false },        
        paymentResponds: { type: DataTypes.JSON},
        sendResponds: {type: DataTypes.JSON},
        status: { type: DataTypes.STRING},
        createdByIP: { type: DataTypes.STRING, allowNull: false },
        createdAt: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
        updatedAt: { type: DataTypes.DATE },        
    };

    const options = {
        // disable default timestamp fields (createdAt and updatedAt)
        timestamps: false,
    };

    return sequelize.define('transaction', attributes, options);
}