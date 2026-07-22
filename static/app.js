document.querySelectorAll('form[data-confirm]').forEach((form)=>form.addEventListener('submit',(event)=>{if(!window.confirm(form.dataset.confirm))event.preventDefault();}));
document.querySelectorAll('.refresh').forEach((button)=>button.addEventListener('click',()=>window.location.reload()));
const workerInput=document.getElementById('workers');
const clampWorkers=(value)=>Math.min(24,Math.max(1,Number.parseInt(value||'1',10)||1));
const workerMinus=document.getElementById('workers-minus');
const workerPlus=document.getElementById('workers-plus');
if(workerInput&&workerMinus)workerMinus.addEventListener('click',()=>{workerInput.value=clampWorkers(Number(workerInput.value)-1);});
if(workerInput&&workerPlus)workerPlus.addEventListener('click',()=>{workerInput.value=clampWorkers(Number(workerInput.value)+1);});
