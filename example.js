const iron = require('./lib/index');
const originalIron = require('@hapi/iron');



iron.seal({
    hello: 'world'
}, 'some_not_random_password_that_is_at_least_32_characters', iron.defaults).then(async (seal) => {
    console.log(seal);
    const data = await iron.unseal(seal, 'some_not_random_password_that_is_at_least_32_characters', iron.defaults);
    console.log(data);
});

// originalIron.seal({
//     hello: 'world'
// }, 'some_not_random_password_that_is_at_least_32_characters', originalIron.defaults).then(async (seal) => {
//     console.log(seal);
//     // const data = await iron.unseal(seal, 'some_not_random_password_that_is_at_least_32_characters', iron.defaults);
//     // console.log(data);
// });


