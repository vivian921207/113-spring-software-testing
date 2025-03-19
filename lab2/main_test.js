const test = require('node:test');
const assert = require('assert');
const fs = require('fs');
const util = require('util');

// 1️⃣ Stub `fs.readFile` 為 Promise 版本
fs.readFile = util.promisify((path, encoding, callback) => {
    callback(null, 'Alice\nBob\nCharlie\nDavid'); // 回傳假名單
});

const { Application, MailSystem } = require('./main'); // 確保這是你的主程式

test('Application getNames should return list of names from stubbed file', async () => {
    const app = new Application();
    await new Promise((resolve) => setTimeout(resolve, 100)); // 確保 `getNames` 完成
    assert.deepStrictEqual(app.people, ['Alice', 'Bob', 'Charlie', 'David']);
});

test('MailSystem write should generate mail content', () => {
    const mailSystem = new MailSystem();
    const name = 'Alice';
    const result = mailSystem.write(name);
    assert.strictEqual(result, 'Congrats, Alice!');
});

test('MailSystem send should return both true and false', () => {
    const mailSystem = new MailSystem();
    const name = 'Alice';
    const context = 'Congrats, Alice!';
    
    let seenTrue = false;
    let seenFalse = false;
    let attempts = 0;
    const maxAttempts = 100; // 限制最大迴圈次數避免無窮迴圈
    
    while (!(seenTrue && seenFalse) && attempts < maxAttempts) {
        const result = mailSystem.send(name, context);
        if (result) {
            seenTrue = true;
        } else {
            seenFalse = true;
        }
        attempts++;
    }
    
    assert.strictEqual(seenTrue, true, 'MailSystem.send() should return true at least once');
    assert.strictEqual(seenFalse, true, 'MailSystem.send() should return false at least once');
});


test('Application getRandomPerson should return a valid person', async () => {
    const app = new Application();
    await new Promise((resolve) => setTimeout(resolve, 100)); // 確保 getNames 完成
    const person = app.getRandomPerson();
    assert.ok(['Alice', 'Bob', 'Charlie', 'David'].includes(person));
});

test('Application selectNextPerson should return null when all are selected', async () => {
    const app = new Application();
    await new Promise((resolve) => setTimeout(resolve, 100));
    app.people = ['Alice', 'Bob'];
    app.selected = ['Alice', 'Bob'];
    const result = app.selectNextPerson();
    assert.strictEqual(result, null);
});

test('Application selectNextPerson should select a new person each time', async () => {
    const app = new Application();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const selected1 = app.selectNextPerson();
    const selected2 = app.selectNextPerson();
    assert.notStrictEqual(selected1, null);
    assert.notStrictEqual(selected2, null);
    assert.notStrictEqual(selected1, selected2);
});

test('Application selectNextPerson should avoid duplicate selection', async () => {
    const app = new Application();
    await new Promise((resolve) => setTimeout(resolve, 100));
    app.people = ['Alice', 'Bob', 'Charlie', 'David'];
    app.selected = ['Alice'];
    const selected = new Set(app.selected);
    for (let i = 0; i < 4; i++) {
        const newPerson = app.selectNextPerson();
        assert.ok(!selected.has(newPerson));
        selected.add(newPerson);
    }
});

test('Application notifySelected should send emails to selected people', async () => {
    const app = new Application();
    await new Promise((resolve) => setTimeout(resolve, 100));
    app.selectNextPerson();
    app.selectNextPerson();
    
    // Spy: 監視方法呼叫次數
    let writeCallCount = 0;
    let sendCallCount = 0;
    
    const originalWrite = app.mailSystem.write;
    const originalSend = app.mailSystem.send;
    
    // Mock: 取代方法回傳預期值
    app.mailSystem.write = () => {
        writeCallCount++;
        return 'Mock Content';
    };
    
    app.mailSystem.send = () => {
        sendCallCount++;
        return true;
    };
    
    app.notifySelected();
    
    assert.strictEqual(writeCallCount, app.selected.length);
    assert.strictEqual(sendCallCount, app.selected.length);
    
    // 還原原始方法
    app.mailSystem.write = originalWrite;
    app.mailSystem.send = originalSend;
});
