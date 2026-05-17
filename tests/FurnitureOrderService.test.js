const FurnitureOrderService = require('../services/FurnitureOrderService');

describe('FurnitureOrderService - 20 Unit Tests', () => {
    let service;
    let mockRepo, mockPayment, mockNotify;

    beforeEach(() => {
        // Створюємо Моки (Mocks)
        mockRepo = { getQuantity: jest.fn(), updateQuantity: jest.fn() };
        mockPayment = { process: jest.fn() };
        mockNotify = { sendConfirmation: jest.fn() };
        service = new FurnitureOrderService(mockRepo, mockPayment, mockNotify);
    });

    // --- ГРУПА 1: HAPPY PATH (Успішні сценарії) ---
    test('1. Успішне замовлення дивана', async () => {
        mockRepo.getQuantity.mockResolvedValue(10);
        mockPayment.process.mockResolvedValue(true);
        const res = await service.placeOrder({ furnitureId: 'sofa', quantity: 1, price: 5000, customerEmail: 'test@ua.com' });
        expect(res.success).toBe(true);
    });

    test('2. Виклик оновлення складу після оплати', async () => {
        mockRepo.getQuantity.mockResolvedValue(5);
        mockPayment.process.mockResolvedValue(true);
        await service.placeOrder({ furnitureId: 'chair', quantity: 2, price: 100, customerEmail: 'a@b.com' });
        expect(mockRepo.updateQuantity).toHaveBeenCalledWith('chair', 3);
    });

    test('3. Відправка email після успіху', async () => {
        mockRepo.getQuantity.mockResolvedValue(1);
        mockPayment.process.mockResolvedValue(true);
        await service.placeOrder({ furnitureId: 'bed', quantity: 1, price: 1000, customerEmail: 'sofia@lviv.ua' });
        expect(mockNotify.sendConfirmation).toHaveBeenCalled();
    });

    // --- ГРУПА 2: ВАЛІДАЦІЯ (Negative Tests) ---
    test('4. Помилка: пустий ID', async () => {
        await expect(service.placeOrder({ quantity: 1 })).rejects.toThrow("ID меблів обов'язкове");
    });

    test('5. Помилка: кількість 0', async () => {
        await expect(service.placeOrder({ furnitureId: 'x', quantity: 0 })).rejects.toThrow("Кількість має бути > 0");
    });

    test('6. Помилка: від\'ємна кількість', async () => {
        await expect(service.placeOrder({ furnitureId: 'x', quantity: -5 })).rejects.toThrow("Кількість має бути > 0");
    });

    test('7. Помилка: від\'ємна ціна', async () => {
        await expect(service.placeOrder({ furnitureId: 'x', quantity: 1, price: -10 })).rejects.toThrow("Ціна не може бути від'ємною");
    });

    test('8. Помилка: некоректний формат email (без @)', async () => {
        await expect(service.placeOrder({ furnitureId: 'x', quantity: 1, price: 10, customerEmail: 'bad-email' }))
            .rejects.toThrow("Некоректний email");
    });

    test('9. Помилка: email не передано', async () => {
        await expect(service.placeOrder({ furnitureId: 'x', quantity: 1, price: 10 }))
            .rejects.toThrow("Некоректний email");
    });

    // --- ГРУПА 3: БІЗНЕС-ЛОГІКА ТА СКЛАД ---
    test('10. Помилка: товару немає на складі (0 шт)', async () => {
        mockRepo.getQuantity.mockResolvedValue(0);
        await expect(service.placeOrder({ furnitureId: 'table', quantity: 1, price: 10, customerEmail: 'a@b.com' }))
            .rejects.toThrow(/Недостатньо товару/);
    });

    test('11. Помилка: замовлено більше, ніж є', async () => {
        mockRepo.getQuantity.mockResolvedValue(5);
        await expect(service.placeOrder({ furnitureId: 'table', quantity: 6, price: 10, customerEmail: 'a@b.com' }))
            .rejects.toThrow("Недостатньо товару. На складі лише: 5");
    });

    test('12. Перевірка цілісності: якщо складу мало, оплата не викликається', async () => {
        mockRepo.getQuantity.mockResolvedValue(2);
        try { await service.placeOrder({ furnitureId: 'x', quantity: 10, price: 10, customerEmail: 'a@b.com' }); } catch {}
        expect(mockPayment.process).not.toHaveBeenCalled();
    });

    // --- ГРУПА 4: ОПЛАТА (Payment Gateway) ---
    test('13. Помилка: банк відхилив платіж', async () => {
        mockRepo.getQuantity.mockResolvedValue(100);
        mockPayment.process.mockResolvedValue(false);
        await expect(service.placeOrder({ furnitureId: 'x', quantity: 1, price: 100, customerEmail: 'a@b.com' }))
            .rejects.toThrow("Платіж відхилено банком");
    });

    test('14. Розрахунок суми: платіж отримує правильну суму (цена * кількість)', async () => {
        mockRepo.getQuantity.mockResolvedValue(10);
        mockPayment.process.mockResolvedValue(true);
        await service.placeOrder({ furnitureId: 'x', quantity: 3, price: 200, customerEmail: 'a@b.com' });
        expect(mockPayment.process).toHaveBeenCalledWith(600);
    });

    test('15. Безкоштовний товар (ціна 0) проходить успішно', async () => {
        mockRepo.getQuantity.mockResolvedValue(10);
        mockPayment.process.mockResolvedValue(true);
        const res = await service.placeOrder({ furnitureId: 'promo', quantity: 1, price: 0, customerEmail: 'a@b.com' });
        expect(res.success).toBe(true);
    });

    // --- ГРУПА 5: ВЗАЄМОДІЯ ТА ГРАНИЧНІ СТАННИ ---
    test('16. Якщо оплата не пройшла, склад НЕ оновлюється', async () => {
        mockRepo.getQuantity.mockResolvedValue(10);
        mockPayment.process.mockResolvedValue(false);
        try { await service.placeOrder({ furnitureId: 'x', quantity: 1, price: 10, customerEmail: 'a@b.com' }); } catch {}
        expect(mockRepo.updateQuantity).not.toHaveBeenCalled();
    });

    test('17. Замовлення останньої одиниці товару', async () => {
        mockRepo.getQuantity.mockResolvedValue(1);
        mockPayment.process.mockResolvedValue(true);
        await service.placeOrder({ furnitureId: 'last', quantity: 1, price: 10, customerEmail: 'a@b.com' });
        expect(mockRepo.updateQuantity).toHaveBeenCalledWith('last', 0);
    });

    test('18. Перевірка виклику getQuantity рівно 1 раз', async () => {
        mockRepo.getQuantity.mockResolvedValue(10);
        mockPayment.process.mockResolvedValue(true);
        await service.placeOrder({ furnitureId: 'x', quantity: 1, price: 10, customerEmail: 'a@b.com' });
        expect(mockRepo.getQuantity).toHaveBeenCalledTimes(1);
    });

    test('19. Помилка: репозиторій складу видав Exception', async () => {
        mockRepo.getQuantity.mockRejectedValue(new Error("DB Error"));
        await expect(service.placeOrder({ furnitureId: 'x', quantity: 1, price: 10, customerEmail: 'a@b.com' }))
            .rejects.toThrow("DB Error");
    });

    test('20. Повна інтеграція моків у ланцюжку', async () => {
        mockRepo.getQuantity.mockResolvedValue(50);
        mockPayment.process.mockResolvedValue(true);
        const res = await service.placeOrder({ furnitureId: 'chair', quantity: 5, price: 100, customerEmail: 'user@test.com' });
        expect(res.status).toBe("ORDER_PROCESSED");
    });
});
