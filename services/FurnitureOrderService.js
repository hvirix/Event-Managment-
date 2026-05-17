class FurnitureOrderService {
    constructor(repo, payment, notify) {
        this.repo = repo;
        this.payment = payment;
        this.notify = notify;
    }

    async placeOrder(order) {
        const { furnitureId, quantity, price, customerEmail } = order || {};

        // 1. Validation
        if (!furnitureId) {
            throw new Error("ID меблів обов'язкове");
        }
        if (quantity === undefined || quantity <= 0) {
            throw new Error("Кількість має бути > 0");
        }
        if (price !== undefined && price < 0) {
            throw new Error("Ціна не може бути від'ємною");
        }
        if (!customerEmail || !customerEmail.includes('@')) {
            throw new Error("Некоректний email");
        }

        // 2. Check Inventory (throws if DB fails, as per Test 19)
        const stock = await this.repo.getQuantity(furnitureId);
        if (stock === 0 || stock < quantity) {
            throw new Error(`Недостатньо товару. На складі лише: ${stock}`);
        }

        // 3. Process Payment (Test 14: amount = price * quantity)
        const totalAmount = price * quantity;
        const paymentSuccess = await this.payment.process(totalAmount);
        if (!paymentSuccess) {
            throw new Error("Платіж відхилено банком");
        }

        // 4. Update Inventory
        const newQuantity = stock - quantity;
        await this.repo.updateQuantity(furnitureId, newQuantity);

        // 5. Send Confirmation Notification
        await this.notify.sendConfirmation(customerEmail, furnitureId);

        return {
            success: true,
            status: "ORDER_PROCESSED"
        };
    }
}

module.exports = FurnitureOrderService;
