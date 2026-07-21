document.querySelectorAll('form[data-confirm]').forEach((form)=>form.addEventListener('submit',(event)=>{if(!window.confirm(form.dataset.confirm))event.preventDefault();}));
document.querySelectorAll('.refresh').forEach((button)=>button.addEventListener('click',()=>window.location.reload()));
